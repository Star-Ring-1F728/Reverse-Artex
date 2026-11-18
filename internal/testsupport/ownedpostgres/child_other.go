//go:build !windows

package ownedpostgres

import "os/exec"

func configureChild(c *exec.Cmd) {}
