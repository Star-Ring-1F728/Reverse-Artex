//go:build linux

package hostresponse

import (
	"os"
	"syscall"
)

func lockSignedOwner(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func unlockSignedOwner(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
