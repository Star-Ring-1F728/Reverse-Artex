//go:build !linux && !windows

package localassistant

import "os"

func replaceState(from, to string) error { return os.Rename(from, to) }
