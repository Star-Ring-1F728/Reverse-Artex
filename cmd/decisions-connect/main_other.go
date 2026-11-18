//go:build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, func() int {
		fmt.Fprintln(os.Stderr, "Windows native credential entry only; on this OS configure a server environment variable.")
		return 2
	}))
}
