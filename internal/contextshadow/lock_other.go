//go:build !linux && !windows

package contextshadow

import (
	"errors"
	"os"
)

func lockOwner(f *os.File) error { return errors.New("case memory locking requires Windows or Linux") }

func unlockOwner(f *os.File) {}
