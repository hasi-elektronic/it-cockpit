//go:build !windows

package main

import "syscall"

// detachedSysProcAttr — non-Windows stub. Self-update is Windows-only,
// so this is just to keep the build green on Linux/Mac dev machines.
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
