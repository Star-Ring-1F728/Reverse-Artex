package actioncontext

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed observation.go
var sources embed.FS

func SourceSHA() string {
	b, _ := sources.ReadFile("observation.go")
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
