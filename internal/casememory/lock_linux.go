//go:build linux

package casememory

import (
	"os"
	"syscall"
)

func replaceState(from, to string) error { return os.Rename(from, to) }
func lockOwner(f *os.File) error         { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockOwner(f *os.File)             { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
