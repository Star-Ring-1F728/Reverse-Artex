//go:build windows

package evidence

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var storageKernel = syscall.NewLazyDLL("kernel32.dll")
var storageLockFile = storageKernel.NewProc("LockFileEx")
var storageUnlockFile = storageKernel.NewProc("UnlockFileEx")

func lockStorage(f *os.File) error {
	var overlap syscall.Overlapped
	ok, _, err := storageLockFile.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok == 0 {
		return err
	}
	return nil
}

func unlockStorage(f *os.File) {
	var overlap syscall.Overlapped
	storageUnlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
}

func regularStorageFile(path string, _ os.FileInfo) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(name, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("linked storage entry refused")
	}
	return nil
}
