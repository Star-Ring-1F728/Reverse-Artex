//go:build windows

package storagebudget

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var lockProc = kernel.NewProc("LockFileEx")
var unlockProc = kernel.NewProc("UnlockFileEx")

func lock(f *os.File) error {
	end := time.Now().Add(2 * time.Second)
	for {
		overlap := syscall.Overlapped{}
		ok, _, e := lockProc.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
		if ok != 0 {
			return nil
		}
		if e != syscall.Errno(33) || time.Now().After(end) {
			return e
		}
		time.Sleep(time.Millisecond)
	}
}
func unlock(f *os.File) {
	o := syscall.Overlapped{}
	unlockProc.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&o)))
}
func regular(path string, info os.FileInfo) error {
	name, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	h, e := syscall.CreateFile(name, 0, 7, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	var data syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(h, &data); e != nil {
		return e
	}
	if data.NumberOfLinks != 1 || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrScope
	}
	return nil
}
