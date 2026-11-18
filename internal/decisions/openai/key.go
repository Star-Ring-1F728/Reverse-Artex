package openai

import (
	"io"
	"os"
	"path/filepath"
)

func ResolveKey(c Config) string {
	if c.Mode == "off" || c.Mode == "fake" {
		return ""
	}
	if c.KeyFile == "" {
		return os.Getenv(c.KeyEnv)
	}
	path, err := filepath.Abs(c.KeyFile)
	if err != nil {
		return ""
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return ""
	}
	return unsealKey(raw)
}
