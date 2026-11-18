//go:build linux

package investigation

import (
	"os"
	"syscall"
)

func openHandoffFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
