//go:build windows

package responsev2

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var retentionKernel = syscall.NewLazyDLL("kernel32.dll")
var retentionVolumePath = retentionKernel.NewProc("GetVolumePathNameW")
var retentionDriveType = retentionKernel.NewProc("GetDriveTypeW")
var retentionVolumeInfo = retentionKernel.NewProc("GetVolumeInformationW")
var retentionMoveFile = retentionKernel.NewProc("MoveFileExW")
var retentionLockFile = retentionKernel.NewProc("LockFileEx")
var retentionUnlockFile = retentionKernel.NewProc("UnlockFileEx")

func retentionSupported() bool { return true }

func validateRetentionPath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	parent := filepath.Dir(absolute)
	var directory string
	for {
		directory, err = filepath.EvalSymlinks(parent)
		if err == nil {
			break
		}
		next := filepath.Dir(parent)
		if !os.IsNotExist(err) || next == parent {
			return err
		}
		parent = next
	}
	name, err := retentionPathName(directory)
	if err != nil {
		return err
	}
	const driveFixed = 3
	var volume [32768]uint16
	ok, _, err := retentionVolumePath.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&volume[0])), uintptr(len(volume)))
	if ok == 0 {
		return err
	}
	drive, _, _ := retentionDriveType.Call(uintptr(unsafe.Pointer(&volume[0])))
	if drive != driveFixed {
		return errors.New("retained V2 journal requires a fixed local NTFS volume")
	}
	var filesystem [32]uint16
	ok, _, err = retentionVolumeInfo.Call(uintptr(unsafe.Pointer(&volume[0])), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&filesystem[0])), uintptr(len(filesystem)))
	if ok == 0 {
		return err
	}
	if syscall.UTF16ToString(filesystem[:]) != "NTFS" {
		return errors.New("retained V2 journal requires a fixed local NTFS volume")
	}
	return nil
}

func retentionPathName(path string) (*uint16, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(absolute, `\\?\UNC\`) || strings.HasPrefix(absolute, `\\.\`) {
		return nil, ErrUnavailable
	}
	if !strings.HasPrefix(absolute, `\\?\`) {
		if strings.HasPrefix(absolute, `\\`) {
			return nil, ErrUnavailable
		}
		absolute = `\\?\` + absolute
	}
	return syscall.UTF16PtrFromString(absolute)
}

func syncRetentionDirectory(path string) error {
	name, err := retentionPathName(path)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	return errors.Join(syscall.FlushFileBuffers(handle), syscall.CloseHandle(handle))
}

func publishRetentionPointer(from, to string) error {
	source, err := retentionPathName(from)
	if err != nil {
		return err
	}
	destination, err := retentionPathName(to)
	if err != nil {
		return err
	}
	const replaceExisting = 0x1
	const writeThrough = 0x8
	// No copy fallback: publication must stay on the same NTFS volume.
	ok, _, err := retentionMoveFile.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(destination)), replaceExisting|writeThrough)
	if ok == 0 {
		return err
	}
	if err = syncRetentionDirectory(filepath.Dir(to)); err != nil {
		return err
	}
	if filepath.Dir(from) != filepath.Dir(to) {
		return syncRetentionDirectory(filepath.Dir(from))
	}
	return nil
}

func lockRetentionRead(file *os.File) error {
	var overlap syscall.Overlapped
	const failImmediately = 0x1
	ok, _, err := retentionLockFile.Call(file.Fd(), failImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
	if ok == 0 {
		return err
	}
	return nil
}

func unlockRetentionRead(file *os.File) {
	var overlap syscall.Overlapped
	retentionUnlockFile.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&overlap)))
}
