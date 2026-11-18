//go:build !linux

package investigation

import (
	"errors"
	"os"
)

func openHandoffFile(path string) (*os.File, error) {
	return nil, errors.New("Linux hosted handoff required")
}
