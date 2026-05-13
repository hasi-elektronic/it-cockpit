//go:build windows

package main

import "syscall"

// detachedSysProcAttr returns SysProcAttr that detaches the child process
// from the parent on Windows (DETACHED_PROCESS = 0x08).
func detachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: 0x00000008, // DETACHED_PROCESS
	}
}
