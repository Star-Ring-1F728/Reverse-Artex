package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

type desktopConfig struct {
	Listen      string   `json:"listen"`
	DataDir     string   `json:"data_dir"`
	Correlation string   `json:"correlation"`
	SensorID    string   `json:"sensor_id"`
	AssetID     string   `json:"asset_id"`
	Tenants     []string `json:"tenants"`
	SensorToken string   `json:"sensor_token,omitempty"`
}

func randomKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func configureDesktop(path string, addr, out, correlation *string) (*desktopConfig, string, error) {
	cfg := &desktopConfig{Listen: "127.0.0.1:9081", DataDir: "data/collector", Correlation: "session", SensorID: "lab-app", AssetID: "lab-api", Tenants: []string{"alpha", "beta", "public"}}
	data, err := os.ReadFile(path)
	create := os.IsNotExist(err)
	if err != nil && !create {
		return nil, "", err
	}
	if !create {
		if len(data) > 16384 {
			return nil, "", errors.New("config.json exceeds 16 KiB")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(cfg); err != nil {
			return nil, "", fmt.Errorf("invalid config: %w", err)
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return nil, "", errors.New("one JSON config object required")
		}
	}
	changed := false
	if cfg.SensorToken == "" {
		cfg.SensorToken, err = randomKey()
		if err != nil {
			return nil, "", err
		}
		changed = true
	}
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if provided["listen"] {
		cfg.Listen = *addr
	}
	if provided["out"] {
		cfg.DataDir = *out
	}
	if provided["correlation"] {
		cfg.Correlation = *correlation
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, "", errors.New("console listen must be a loopback host:port")
	}
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if (host != "localhost" && (ip == nil || !ip.IsLoopback())) || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, "", errors.New("console requires a loopback address and port 1..65535")
	}
	if cfg.DataDir == "" || len(cfg.Tenants) == 0 || cfg.SensorID == "" || cfg.AssetID == "" || len(cfg.SensorToken) < 32 || (cfg.Correlation != "session" && cfg.Correlation != "principal") {
		return nil, "", errors.New("invalid console data, sensor, tenant or correlation settings")
	}
	id := regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	if !id.MatchString(cfg.SensorID) || !id.MatchString(cfg.AssetID) {
		return nil, "", errors.New("invalid sensor or asset identifier")
	}
	seen := map[string]bool{}
	for _, tenant := range cfg.Tenants {
		if !id.MatchString(tenant) || seen[tenant] {
			return nil, "", errors.New("invalid or duplicate tenant identifier")
		}
		seen[tenant] = true
	}
	if create || changed {
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return nil, "", err
		}
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, "", err
		}
		mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if !create {
			mode = os.O_WRONLY | os.O_TRUNC
		}
		f, err := os.OpenFile(path, mode, 0600)
		if err != nil {
			return nil, "", err
		}
		_, writeErr := f.Write(append(data, '\n'))
		syncErr := f.Sync()
		closeErr := f.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return nil, "", err
		}
	}
	*addr, *out, *correlation = cfg.Listen, cfg.DataDir, cfg.Correlation
	for name, value := range map[string]string{"RA_SENSOR_TOKEN": cfg.SensorToken, "RA_SENSOR_ID": cfg.SensorID, "RA_ASSET_ID": cfg.AssetID} {
		if os.Getenv(name) == "" {
			if err := os.Setenv(name, value); err != nil {
				return nil, "", err
			}
		}
	}
	if os.Getenv("RA_TENANTS") == "" {
		encoded := ""
		for i, tenant := range cfg.Tenants {
			if i > 0 {
				encoded += ","
			}
			encoded += tenant
		}
		if err := os.Setenv("RA_TENANTS", encoded); err != nil {
			return nil, "", err
		}
	}
	key, err := randomKey()
	return cfg, key, err
}
