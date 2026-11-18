package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reverse-artex/internal/evidence"
)

const operationsSchema = "reverse-artex-operations/1"

type operationsFloor struct {
	Acked    int64  `json:"acked"`
	AckedIDs string `json:"acked_ids_sha256"`
}

type operationsState struct {
	Schema         string            `json:"schema"`
	Deployment     string            `json:"deployment_id"`
	Root           string            `json:"root"`
	Limit          int64             `json:"limit_bytes"`
	Generation     int64             `json:"generation"`
	AuthEpoch      int64             `json:"auth_epoch"`
	Phase          string            `json:"phase"`
	Roles          map[string]string `json:"roles"`
	Credentials    map[string]string `json:"credentials"`
	CollectorScope map[string]string `json:"collector_scope"`
	Floor          *operationsFloor  `json:"floor"`
	Profile        struct {
		Correlation string   `json:"correlation"`
		Canaries    []string `json:"canaries"`
	} `json:"profile"`
}

// A proposed checkpoint must satisfy its current app ACK prefix as well as
// the previously anchored floor. Only authenticated offline recovery uses it.
func recoveryACKFloor(acked int64, ids string, recovery bool, operationsPath string) (*operationsFloor, error) {
	if acked == -1 && ids == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(ids)
	if !recovery || operationsPath == "" || acked < 0 || acked > 200000 || err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("checkpoint ACK prefix requires signed operations recovery and bounded count/hash")
	}
	return &operationsFloor{Acked: acked, AckedIDs: hex.EncodeToString(decoded)}, nil
}

func verifyCollectorFloor(store *evidence.Store, state *operationsState) error {
	if state == nil || state.Floor == nil {
		return nil
	}
	return verifyCollectorACKPrefix(store, state.CollectorScope["RA_SENSOR_ID"], state.Floor)
}

func verifyCollectorACKPrefix(store *evidence.Store, sensor string, floor *operationsFloor) error {
	if floor.Acked < 0 || floor.Acked > 200000 {
		return errors.New("invalid anchored ACK count")
	}
	count, ids := int64(0), sha256.New()
	err := store.VisitRecords("events", func(raw []byte) error {
		var record struct {
			ID     string `json:"event_id"`
			Sensor string `json:"sensor_id"`
		}
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}
		if record.Sensor != sensor {
			return nil
		}
		count++
		if count <= floor.Acked {
			var length [4]byte
			binary.BigEndian.PutUint32(length[:], uint32(len(record.ID)))
			ids.Write(length[:])
			ids.Write([]byte(record.ID))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count < floor.Acked || !operationsEqual(floor.AckedIDs, hex.EncodeToString(ids.Sum(nil))) {
		return errors.New("collector does not match required ACK prefix")
	}
	return nil
}

type operationsMarker struct {
	Schema     string `json:"schema"`
	Deployment string `json:"deployment_id"`
	StatePath  string `json:"state_path"`
	Generation int64  `json:"generation"`
}

func readOperationsFile(path string, result any) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return errors.New("operations file unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("linked operations file refused")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("operations file unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil || len(raw) > 32768 {
		return errors.New("invalid operations file")
	}
	var envelope struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil {
		return errors.New("invalid operations envelope")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing operations envelope")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return errors.New("invalid operations payload")
	}
	key := os.Getenv("RA_OPS_SIGNING_KEY")
	if len(key) < 32 || len(key) > 512 {
		return errors.New("operations signing credential required")
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return errors.New("operations signature mismatch")
	}
	if err = json.Unmarshal(payload, result); err != nil {
		return errors.New("invalid operations state")
	}
	return nil
}

func operationsDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func operationsEqual(a, b string) bool { return len(a) == 64 && hmac.Equal([]byte(a), []byte(b)) }

var operationsCollectorDefaults = map[string]string{
	"RA_SENSOR_ID": "lab-app", "RA_ASSET_ID": "lab-api", "RA_TENANTS": "alpha,beta,public",
	"RA_HOST_SENSOR_ID": "lab-host", "RA_HOST_TENANT": "alpha", "RA_HOST_SERVICE_ID": "lab-web", "RA_HOST_WORKLOAD_ID": "lab-workload",
}

func loadOperations(path, root string, limit int64, pending bool) (*operationsState, error) {
	var state operationsState
	if err := readOperationsFile(path, &state); err != nil {
		return nil, err
	}
	if state.Schema != operationsSchema || state.Root != root || state.Limit != limit || len(state.Deployment) != 32 || state.Generation < 0 || state.AuthEpoch < 1 {
		return nil, errors.New("operations deployment mismatch")
	}
	var marker operationsMarker
	if err := readOperationsFile(filepath.Join(root, ".operations.json"), &marker); err != nil {
		return nil, err
	}
	if marker.Schema != operationsSchema || marker.Deployment != state.Deployment || marker.StatePath != path {
		return nil, errors.New("operations anchor mismatch")
	}
	if pending {
		if !operationsEqual(state.Roles["admin"], operationsDigest(os.Getenv("RA_OPS_ADMIN_TOKEN"))) {
			return nil, errors.New("operations admin required for recovery check")
		}
	} else if state.Phase != "active" || marker.Generation != state.Generation {
		return nil, errors.New("operations restore/generation gate closed")
	}
	if !operationsEqual(state.Credentials["RA_SENSOR_TOKEN"], operationsDigest(os.Getenv("RA_SENSOR_TOKEN"))) {
		return nil, errors.New("sensor credential mismatch")
	}
	for _, name := range []string{"RA_WAF_SENSOR_TOKEN", "RA_HOST_SENSOR_TOKEN"} {
		actual, configured := os.Getenv(name), state.Credentials[name]
		if (actual == "") != (configured == "") || actual != "" && !operationsEqual(configured, operationsDigest(actual)) {
			return nil, errors.New("optional sensor credential mismatch")
		}
	}
	if len(state.CollectorScope) != len(operationsCollectorDefaults) {
		return nil, errors.New("collector scope missing")
	}
	for name, fallback := range operationsCollectorDefaults {
		actual := os.Getenv(name)
		if actual == "" {
			actual = fallback
		}
		if state.CollectorScope[name] != actual {
			return nil, errors.New("collector scope mismatch")
		}
	}
	return &state, nil
}

// Reload roles on every request so revocation does not wait for a restart.
func operationsHandler(next http.Handler, path, root string, limit int64) http.Handler {
	if path == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := loadOperations(path, root, limit, false)
		if err != nil {
			http.Error(w, "operations gate closed", 503)
			return
		}
		if r.URL.Path == "/health" {
			header := r.Header.Get("Authorization")
			if len(header) < 7 || len(header) > 519 || header[:7] != "Bearer " {
				http.Error(w, "unauthorized", 401)
				return
			}
			hash := operationsDigest(header[7:])
			if operationsEqual(state.Credentials["RA_SENSOR_TOKEN"], hash) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"mode": "observe", "policy_forwarding_configured": false})
				return
			}
			if !operationsEqual(state.Roles["reader"], hash) && !operationsEqual(state.Roles["admin"], hash) && !operationsEqual(state.Credentials["RA_SENSOR_TOKEN"], hash) {
				http.Error(w, "unauthorized", 401)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
