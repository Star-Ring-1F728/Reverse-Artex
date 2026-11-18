//go:build windows

// decisions-connect is a native console credential entry point. It does not
// run scripts or change PowerShell/Windows execution or security policies.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	api "reverse-artex/internal/decisions/openai"
	"syscall"
	"time"
	"unsafe"
)

func hiddenInput() ([]byte, error) {
	handle, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return nil, fmt.Errorf("interactive console required")
	}
	kernel := syscall.NewLazyDLL("kernel32.dll")
	var mode uint32
	ok, _, _ := kernel.NewProc("GetConsoleMode").Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if ok == 0 {
		return nil, fmt.Errorf("interactive console required")
	}
	ok, _, _ = kernel.NewProc("SetConsoleMode").Call(uintptr(handle), uintptr(mode&^4))
	if ok == 0 {
		return nil, fmt.Errorf("hidden input unavailable")
	}
	defer kernel.NewProc("SetConsoleMode").Call(uintptr(handle), uintptr(mode))
	raw, err := bufio.NewReaderSize(os.Stdin, 4097).ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("input incomplete")
	}
	key := append([]byte{}, bytes.TrimRight(raw, "\r\n")...)
	for n := range raw {
		raw[n] = 0
	}
	return key, nil
}
func connect() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root := filepath.Dir(filepath.Dir(exe))
	fmt.Println("Reverse Artex Decisions connection")
	fmt.Println("This native app does not change PowerShell execution policies.")
	fmt.Println("The API key is not displayed or written as plaintext.")
	fmt.Println("It will be encrypted for this Windows user and reused by the app.")
	fmt.Print("OPENAI_API_KEY (hidden input): ")
	key := []byte(os.Getenv("OPENAI_API_KEY"))
	if len(key) < 16 {
		key, err = hiddenInput()
		fmt.Println()
		if err != nil {
			return err
		}
	} else {
		fmt.Println("using configured process credential")
	}
	defer func() {
		for n := range key {
			key[n] = 0
		}
	}()
	if len(key) < 16 || len(key) > 4096 {
		return fmt.Errorf("no valid key entered")
	}
	for _, c := range key {
		if c <= 32 || c >= 127 {
			return fmt.Errorf("invalid key characters")
		}
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	secretDir := filepath.Join(root, "data", "secrets")
	if err = os.MkdirAll(secretDir, 0700); err != nil {
		return err
	}
	keyPath := filepath.Join(secretDir, "decisions-"+stamp+".dpapi")
	if err = api.SealKey(keyPath, key); err != nil {
		return err
	}
	cfg := api.Config{Revision: stamp, Mode: "shadow", KeyFile: keyPath, DailyCalls: 100, DailyTokens: 1000000, ReserveTokens: 8192}
	configPath := filepath.Join(root, "config.decisions-"+stamp+".local.json")
	file, err := os.OpenFile(configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(file).Encode(cfg); err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return err
	}
	fmt.Println("Encrypted credential and shadow configuration saved.")
	fmt.Println("Config:", configPath)
	resultDir := filepath.Join(root, ".workspace-copy", "v2-implementation-20261101")
	if err = os.MkdirAll(resultDir, 0700); err != nil {
		return err
	}
	resultPath := filepath.Join(resultDir, "live-smoke-"+stamp+".json")
	cmd := exec.Command(filepath.Join(root, "bin", "decisions-check.exe"), "-live", "-key-file", keyPath, "-out", resultPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	fmt.Println("Result:", resultPath)
	return err
}
func connectInteractive() int {
	if err := connect(); err != nil {
		fmt.Println("Connection setup did not complete. No key value is included in this message.")
	}
	fmt.Println("Press Enter to close.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return 0
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, connectInteractive))
}
