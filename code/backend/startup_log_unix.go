//go:build unix

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether file is a terminal. Only a terminal answers the
// window-size request; a file, a pipe, a socket and /dev/null all refuse it.
// That request, unlike the termios one, has the same name on every Unix, so
// one file covers macOS and the Linux tests alike.
func isTerminal(file *os.File) bool {
	connection, err := file.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	_ = connection.Control(func(descriptor uintptr) {
		_, err := unix.IoctlGetWinsize(int(descriptor), unix.TIOCGWINSZ)
		terminal = err == nil
	})
	return terminal
}
