package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopRejectsInvalidConfigWithoutReplacingIt(t *testing.T) {
	for _, input := range []string{`{"listen":"0.0.0.0:9081"}`, `{"database":{"password":"keep-me"}}`, `{"tenants":["alpha","alpha"]}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		addr, out, correlation := "", "", ""
		if _, _, err := configureDesktop(path, &addr, &out, &correlation); err == nil {
			t.Fatalf("invalid config accepted: %s", input)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != input {
			t.Fatal("invalid config was modified")
		}
	}
}

func TestDesktopKeepsSensorCredentialAndRotatesConsoleAccess(t *testing.T) {
	for _, name := range []string{"RA_SENSOR_TOKEN", "RA_SENSOR_ID", "RA_ASSET_ID", "RA_TENANTS"} {
		t.Setenv(name, "")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	addr, out, correlation := "", "", ""
	first, firstKey, err := configureDesktop(path, &addr, &out, &correlation)
	if err != nil {
		t.Fatal(err)
	}
	second, secondKey, err := configureDesktop(path, &addr, &out, &correlation)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.SensorToken) != 64 || first.SensorToken != second.SensorToken || firstKey == secondKey || firstKey == first.SensorToken || len(secondKey) != 64 {
		t.Fatal("credential lifecycle contract failed")
	}
	if addr != "127.0.0.1:9081" || out != "data/collector" {
		t.Fatal("unexpected default deployment layout")
	}
}
