//go:build windows

package actionapproval

import (
	"os"
	"syscall"
	"unsafe"
)

// Same byte-range ownership pattern used by the existing assistance store.
var kernel = syscall.NewLazyDLL("kernel32.dll")
var lockFile = kernel.NewProc("LockFileEx")
var unlockFile = kernel.NewProc("UnlockFileEx")

func lockOwner(f *os.File) error {
	o := syscall.Overlapped{}
	ok, _, err := lockFile.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if ok == 0 {
		return err
	}
	return nil
}
func unlockOwner(f *os.File) {
	o := syscall.Overlapped{}
	unlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&o)))
}
