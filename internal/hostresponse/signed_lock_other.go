//go:build !linux && !windows

package hostresponse

import (
	"errors"
	"os"
)

func lockSignedOwner(*os.File) error {
	return errors.New("signed host ownership unsupported on this platform")
}
func unlockSignedOwner(*os.File) {}
