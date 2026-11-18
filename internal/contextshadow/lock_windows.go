//go:build windows

package contextshadow

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func replaceState(from, to string) error {
	end := time.Now().Add(200 * time.Millisecond)
	for {
		err := os.Rename(from, to)
		if err == nil {
			return nil
		}
		if (!errors.Is(err, syscall.Errno(5)) && !errors.Is(err, syscall.Errno(32)) && !errors.Is(err, syscall.Errno(33))) || !time.Now().Before(end) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var lockProc = kernel.NewProc("LockFileEx")
var unlockProc = kernel.NewProc("UnlockFileEx")

func lockOwner(f *os.File) error {
	o := syscall.Overlapped{}
	ok, _, err := lockProc.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if ok == 0 {
		return err
	}
	return nil
}
func unlockOwner(f *os.File) {
	o := syscall.Overlapped{}
	unlockProc.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&o)))
}
