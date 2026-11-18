//go:build windows

package openai

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func TestDPAPICurrentUserSourceAndOffNeverReadsIt(t *testing.T) {
	key := []byte("synthetic-fixture-credential-only")
	purpose := []byte("ReverseArtex.Decisions.v1")
	in := blob{uint32(len(key)), &key[0]}
	entropy := blob{uint32(len(purpose)), &purpose[0]}
	var out blob
	ok, _, err := crypt32.NewProc("CryptProtectData").Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&entropy)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	if ok == 0 {
		t.Fatal("DPAPI protect failed", err)
	}
	encrypted := append([]byte{}, unsafe.Slice(out.Data, int(out.Size))...)
	localFree.Call(uintptr(unsafe.Pointer(out.Data)))
	if bytes.Contains(encrypted, key) {
		t.Fatal("credential persisted as plaintext")
	}
	path := filepath.Join(t.TempDir(), "credential.dpapi")
	if err := os.WriteFile(path, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: "shadow", KeyFile: path}
	if ResolveKey(cfg) != string(key) {
		t.Fatal("DPAPI credential did not resolve")
	}
	cfg.Mode = "off"
	if ResolveKey(cfg) != "" {
		t.Fatal("off resolved a credential")
	}
	cfg.Mode = "shadow"
	cfg.KeyFile = path + ".missing"
	if ResolveKey(cfg) != "" {
		t.Fatal("missing credential returned data")
	}
	cfg.KeyFile = path
	os.WriteFile(path, []byte("invalid-encrypted-value"), 0600)
	if ResolveKey(cfg) != "" {
		t.Fatal("invalid DPAPI credential accepted")
	}
}
