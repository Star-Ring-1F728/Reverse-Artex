package event

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed event.go
var contextSource embed.FS

func ContextContractSHA() string {
	b, _ := contextSource.ReadFile("event.go")
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
