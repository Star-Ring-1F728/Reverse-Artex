//go:build linux

package storagebudget

import (
	"os"
	"syscall"
	"time"
)

func lock(f *os.File) error {
	end := time.Now().Add(2 * time.Second)
	for {
		e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return nil
		}
		if e != syscall.EWOULDBLOCK || time.Now().After(end) {
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func unlock(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func regular(path string, info os.FileInfo) error {
	if info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return ErrScope
	}
	return nil
}
