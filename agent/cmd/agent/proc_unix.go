//go:build !windows

package main

import "os/exec"

func hideConsoleWindow(cmd *exec.Cmd) {
	// no-op on non-Windows
	_ = cmd
}
