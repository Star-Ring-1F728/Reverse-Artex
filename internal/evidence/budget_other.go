//go:build !windows && !linux

package evidence

import (
	"errors"
	"os"
)

func lockStorage(f *os.File) error {
	return errors.New("shared storage profile supports Windows and Linux")
}
func unlockStorage(f *os.File) {}

func regularStorageFile(_ string, _ os.FileInfo) error {
	return errors.New("shared storage profile supports Windows and Linux")
}
