//go:build linux

package actionapproval

import (
	"os"
	"syscall"
)

func lockOwner(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func unlockOwner(f *os.File)     { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
