//go:build windows

package ownedpostgres

import (
	"os/exec"
	"syscall"
)

func configureChild(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000010, HideWindow: true}
}
