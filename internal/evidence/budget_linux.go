//go:build linux

package evidence

import (
	"errors"
	"os"
	"syscall"
)

func lockStorage(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func unlockStorage(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

func regularStorageFile(_ string, info os.FileInfo) error {
	if info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return errors.New("hardlinked storage entry refused")
	}
	return nil
}
