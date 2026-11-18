// Package ownedpostgres is opt-in TEST SUPPORT ONLY. Production code must not import it.
// It adds a separate verified native fixture lane; existing Unix/container guards remain.
package ownedpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type Spec struct{ Database, Admin string }

var Specs = map[string]Spec{"source-ledger": {"source_ledger_test", "native_source_admin"}, "case-ledger": {"case_ledger_test", "native_case_admin"}, "case-api": {"case_api_test", "native_api_admin"}, "q05-live": {"q05_live_test", "q05_lab_admin"}}

type File struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
}
type Receipt struct {
	Schema     string            `json:"schema"`
	Profile    string            `json:"profile"`
	RunDir     string            `json:"run_dir"`
	DataDir    string            `json:"data_dir"`
	Nonce      string            `json:"nonce"`
	Host       string            `json:"host"`
	Port       uint16            `json:"port"`
	Database   string            `json:"database"`
	Admin      string            `json:"admin"`
	Plan       string            `json:"plan"`
	PlanSHA    string            `json:"plan_sha256"`
	Controller File              `json:"controller"`
	Python     File              `json:"python"`
	PGBin      string            `json:"pg_bin"`
	Inputs     map[string]string `json:"input_sha256"`
	Sources    map[string]string `json:"source_sha256"`
	Tools      map[string]File   `json:"tools"`
	PID        int               `json:"pid"`
	Process    map[string]any    `json:"process_identity"`
	Listener   map[string]any    `json:"listener"`
	SQL        map[string]any    `json:"sql"`
	SystemID   string            `json:"system_identifier"`
}
type Gate struct {
	Approved   bool   `json:"approved"`
	Native     bool   `json:"native_owned_postgres_integration"`
	Profile    string `json:"profile"`
	ReceiptSHA string `json:"runtime_receipt_sha256"`
	PlanSHA    string `json:"plan_sha256"`
}
type Target struct {
	Receipt                                          Receipt
	ReceiptPath, ReceiptSHA, GatePath, GateSHA, Root string
}

var state = struct {
	sync.Mutex
	targets map[string]*Target
	seeded  map[string]bool
}{targets: map[string]*Target{}, seeded: map[string]bool{}}

func Enabled() bool { return os.Getenv("RA_NATIVE_PG_RECEIPT") != "" }
func hash(path string) (string, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func pin(path, want string) error {
	got, e := hash(path)
	if e != nil || len(want) != 64 || got != want {
		return fmt.Errorf("pinned native test input changed")
	}
	return nil
}
func beneath(root, path string) bool {
	r, e := filepath.Rel(root, path)
	return e == nil && r != "." && !filepath.IsAbs(r) && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
}
func noLinks(path string) error {
	p := filepath.Clean(path)
	for {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("native fixture paths cannot traverse links")
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
func repository() (string, error) {
	p, e := os.Getwd()
	if e != nil {
		return "", e
	}
	for {
		raw, e := os.ReadFile(filepath.Join(p, "go.mod"))
		if e == nil && strings.Contains(string(raw), "module reverse-artex") {
			return p, nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", fmt.Errorf("product repository missing")
		}
		p = parent
	}
}
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON depth")
	}
	tok, e := d.Token()
	if e != nil {
		return e
	}
	if delim, ok := tok.(json.Delim); ok {
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				name, ok := k.(string)
				if !ok || seen[name] {
					return fmt.Errorf("duplicate JSON member")
				}
				seen[name] = true
				if len(seen) > 10000 {
					return fmt.Errorf("JSON bound")
				}
				if e = jsonValue(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return fmt.Errorf("JSON object")
			}
		}
		if delim == '[' {
			n := 0
			for d.More() {
				n++
				if n > 10000 {
					return fmt.Errorf("JSON bound")
				}
				if e = jsonValue(d, depth+1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return fmt.Errorf("JSON array")
			}
		}
	}
	return nil
}
func readStrict(path string, value any) error {
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) > 4<<20 {
		return fmt.Errorf("bounded native receipt required")
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	if e = jsonValue(scan, 0); e != nil {
		return e
	}
	if _, e = scan.Token(); e != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(value)
}

// ValidateShape performs no network, SQL, process start or mutation.
func ValidateShape(r Receipt, cfg *pgx.ConnConfig, profile, root string) error {
	spec, ok := Specs[profile]
	if !ok || r.Schema != "root-verified-native-postgres-test/1" || r.Profile != profile {
		return fmt.Errorf("explicit native test profile required")
	}
	if len(r.Nonce) != 32 || strings.ToLower(r.Nonce) != r.Nonce {
		return fmt.Errorf("native nonce missing")
	}
	if _, e := hex.DecodeString(r.Nonce); e != nil {
		return e
	}
	if r.Host != "127.0.0.1" || r.Port < 1024 || r.Database != spec.Database || r.Admin != spec.Admin || cfg.Host != r.Host || cfg.Port != r.Port || cfg.Database != r.Database || cfg.User != r.Admin || cfg.Password != "" || cfg.TLSConfig != nil || len(cfg.Fallbacks) != 0 {
		return fmt.Errorf("refusing arbitrary TCP/database/role/credential")
	}
	if !filepath.IsAbs(r.RunDir) || !beneath(filepath.Join(root, "artifacts"), r.RunDir) || filepath.Clean(r.DataDir) != filepath.Join(r.RunDir, "data") || !beneath(r.RunDir, r.Plan) {
		return fmt.Errorf("fresh owned data/plan scope required")
	}
	if r.Controller.Path != filepath.Join(root, "tools", "owned_postgres_test_lane.py") || r.PID <= 1 || r.SystemID == "" || len(r.Process) == 0 || len(r.Listener) == 0 || len(r.SQL) == 0 {
		return fmt.Errorf("actual native OS/SQL proof required")
	}
	if len(r.PlanSHA) != 64 || len(r.Controller.SHA) != 64 || len(r.Python.SHA) != 64 || len(r.Inputs) == 0 || len(r.Sources) == 0 {
		return fmt.Errorf("exact source/tool pins required")
	}
	for _, name := range []string{"postgres", "pg_ctl", "pg_dump", "pg_restore"} {
		f, ok := r.Tools[name]
		if !ok || filepath.Dir(f.Path) != r.PGBin || len(f.SHA) != 64 {
			return fmt.Errorf("pinned native PG tool required")
		}
	}
	return nil
}
func top(t testing.TB) string { return strings.Split(t.Name(), "/")[0] }
func Require(t testing.TB, profile string, cfg *pgx.ConnConfig, reopen bool) *Target {
	t.Helper()
	root, e := repository()
	if e != nil {
		t.Fatal(e)
	}
	target := &Target{Root: root, ReceiptPath: os.Getenv("RA_NATIVE_PG_RECEIPT"), ReceiptSHA: os.Getenv("RA_NATIVE_PG_RECEIPT_SHA256"), GatePath: os.Getenv("RA_NATIVE_PG_APPROVAL"), GateSHA: os.Getenv("RA_NATIVE_PG_APPROVAL_SHA256")}
	for _, path := range []string{target.ReceiptPath, target.GatePath} {
		if !beneath(filepath.Join(root, "artifacts"), path) || noLinks(path) != nil {
			t.Fatal("owned immutable native receipt/gate required")
		}
	}
	if pin(target.ReceiptPath, target.ReceiptSHA) != nil || pin(target.GatePath, target.GateSHA) != nil || readStrict(target.ReceiptPath, &target.Receipt) != nil {
		t.Fatal("native receipt/gate pin or schema mismatch")
	}
	if e = ValidateShape(target.Receipt, cfg, profile, root); e != nil {
		t.Fatal(e)
	}
	var gate Gate
	if readStrict(target.GatePath, &gate) != nil || !gate.Approved || !gate.Native || gate.Profile != profile || gate.ReceiptSHA != target.ReceiptSHA || gate.PlanSHA != target.Receipt.PlanSHA {
		t.Fatal("fresh root OS/SQL approval binding missing")
	}
	for path, want := range target.Receipt.Inputs {
		if pin(path, want) != nil {
			t.Fatal("native executable/package input changed")
		}
	}
	for name, want := range target.Receipt.Sources {
		p := filepath.Join(root, name)
		if !beneath(root, p) || pin(p, want) != nil {
			t.Fatal("reviewed native test source changed")
		}
	}
	if pin(target.Receipt.Controller.Path, target.Receipt.Controller.SHA) != nil || pin(target.Receipt.Python.Path, target.Receipt.Python.SHA) != nil || pin(target.Receipt.Plan, target.Receipt.PlanSHA) != nil {
		t.Fatal("native controller/Python/plan changed")
	}
	if reopen {
		state.Lock()
		seeded := state.seeded[target.ReceiptSHA]
		state.Unlock()
		if profile != "case-api" || !seeded {
			t.Fatal("reopen requires successful actual seed test in this same process/owned instance")
		}
	}
	mode := "initial"
	if reopen {
		mode = "running"
	}
	target.invoke(t, "verify", "--mode", mode)
	state.Lock()
	state.targets[top(t)] = target
	state.Unlock()
	t.Cleanup(func() {
		target.invoke(t, "verify", "--mode", "running")
		if !t.Failed() && profile == "case-api" && !reopen {
			state.Lock()
			state.seeded[target.ReceiptSHA] = true
			state.Unlock()
		}
	})
	return target
}
func Current(t testing.TB) *Target {
	t.Helper()
	if !Enabled() {
		return nil
	}
	state.Lock()
	v := state.targets[top(t)]
	state.Unlock()
	if v == nil {
		t.Fatal("native target was not verified for this actual test")
	}
	return v
}
func (v *Target) invoke(t testing.TB, action string, args ...string) map[string]any {
	t.Helper()
	for _, p := range []struct{ p, h string }{{v.ReceiptPath, v.ReceiptSHA}, {v.GatePath, v.GateSHA}, {v.Receipt.Controller.Path, v.Receipt.Controller.SHA}, {v.Receipt.Python.Path, v.Receipt.Python.SHA}} {
		if pin(p.p, p.h) != nil {
			t.Fatal("native action input changed")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	argv := []string{"-I", "-B", v.Receipt.Controller.Path, "--action", action, "--receipt", v.ReceiptPath, "--receipt-sha256", v.ReceiptSHA, "--approval", v.GatePath, "--approval-sha256", v.GateSHA}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, v.Receipt.Python.Path, argv...)
	cmd.Env = controllerEnv()
	raw, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("owned native PostgreSQL %s rejected: %v", action, e)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result["verified"] != true {
		t.Fatal("native action proof absent")
	}
	return result
}
func controllerEnv() []string {
	out := []string{}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "PG") {
			out = append(out, value)
		}
	}
	return out
}
func Tool(t testing.TB, name, legacy string) string {
	t.Helper()
	v := Current(t)
	if v == nil {
		return legacy
	}
	f, ok := v.Receipt.Tools[name]
	if !ok || pin(f.Path, f.SHA) != nil {
		t.Fatal("exact native test executable missing or changed")
	}
	return f.Path
}
func (v *Target) Stop(t testing.TB)  { v.invoke(t, "stop") }
func (v *Target) Start(t testing.TB) { v.invoke(t, "start") }
func PrepareChild(t testing.TB, cmd *exec.Cmd) {
	t.Helper()
	if Current(t) != nil {
		configureChild(cmd)
	}
}
func SignalChild(t testing.TB, cmd *exec.Cmd) {
	t.Helper()
	v := Current(t)
	if v == nil {
		t.Fatal("native child signal without verified target")
	}
	v.invoke(t, "signal-child", "--pid", fmt.Sprint(cmd.Process.Pid), "--parent", fmt.Sprint(os.Getpid()), "--binary", cmd.Path)
}
