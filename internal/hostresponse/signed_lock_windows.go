//go:build windows

package hostresponse

import (
	"os"
	"syscall"
	"unsafe"
)

var signedKernel = syscall.NewLazyDLL("kernel32.dll")
var signedLock = signedKernel.NewProc("LockFileEx")
var signedUnlock = signedKernel.NewProc("UnlockFileEx")

func lockSignedOwner(f *os.File) error {
	o := syscall.Overlapped{}
	ok, _, err := signedLock.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if ok == 0 {
		return err
	}
	return nil
}
func unlockSignedOwner(f *os.File) {
	o := syscall.Overlapped{}
	signedUnlock.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&o)))
}
