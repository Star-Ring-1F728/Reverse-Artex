//go:build linux

package responsev2

import (
	"os"
	"path/filepath"
	"syscall"
)

func retentionSupported() bool { return true }
func syncRetentionDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func publishRetentionPointer(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	if err := syncRetentionDirectory(filepath.Dir(to)); err != nil {
		return err
	}
	if filepath.Dir(from) != filepath.Dir(to) {
		return syncRetentionDirectory(filepath.Dir(from))
	}
	return nil
}

func lockRetentionRead(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
}
func unlockRetentionRead(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
