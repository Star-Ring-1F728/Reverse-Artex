//go:build !linux

package responsev2

import (
	"errors"
	"os"
)

func retentionSupported() bool { return false }
func syncRetentionDirectory(string) error {
	return errors.New("retained V2 journals require Linux directory fsync; native platform qualification pending")
}
func publishRetentionPointer(string, string) error {
	return errors.New("retained V2 journals require Linux directory fsync; native platform qualification pending")
}

func lockRetentionRead(*os.File) error {
	return errors.New("native read-only journal verification pending")
}
func unlockRetentionRead(*os.File) {}
