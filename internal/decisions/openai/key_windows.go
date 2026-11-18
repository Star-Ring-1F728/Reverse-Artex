//go:build windows

package openai

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unicode/utf8"
	"unsafe"
)

type blob struct {
	Size uint32
	Data *byte
}

var crypt32 = syscall.NewLazyDLL("crypt32.dll")
var unprotect = crypt32.NewProc("CryptUnprotectData")
var localFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

func unsealKey(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	entropy := []byte("ReverseArtex.Decisions.v1")
	in := blob{uint32(len(raw)), &raw[0]}
	purpose := blob{uint32(len(entropy)), &entropy[0]}
	var out blob
	ok, _, _ := unprotect.Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&purpose)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(raw)
	runtime.KeepAlive(entropy)
	if ok == 0 || out.Data == nil {
		return ""
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.Data)))
	if out.Size < 16 || out.Size > 4096 {
		return ""
	}
	plain := unsafe.Slice(out.Data, int(out.Size))
	defer func() {
		for n := range plain {
			plain[n] = 0
		}
	}()
	if !utf8.Valid(plain) {
		return ""
	}
	return string(plain)
}

// SealKey persists only a DPAPI ciphertext, bound to the current user and app.
func SealKey(path string, key []byte) error {
	if len(key) < 16 || len(key) > 4096 {
		return ErrConfig
	}
	purpose := []byte("ReverseArtex.Decisions.v1")
	in := blob{uint32(len(key)), &key[0]}
	entropy := blob{uint32(len(purpose)), &purpose[0]}
	var out blob
	ok, _, _ := crypt32.NewProc("CryptProtectData").Call(uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&entropy)), 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(key)
	runtime.KeepAlive(purpose)
	if ok == 0 || out.Data == nil {
		return errors.New("Windows credential encryption unavailable")
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.Data)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	raw := unsafe.Slice(out.Data, int(out.Size))
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return errors.New("encrypted credential write failed")
	}
	return f.Sync()
}
