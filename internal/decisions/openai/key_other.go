//go:build !windows

package openai

func unsealKey([]byte) string { return "" }
