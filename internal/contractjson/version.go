package contractjson

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed decode.go
var source embed.FS

func SourceSHA() string {
	b, _ := source.ReadFile("decode.go")
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
