//go:build !windows

package rendezvous

import "syscall"

// processAlive reports whether the record's PID still exists. EPERM means it
// exists but belongs to another user.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
