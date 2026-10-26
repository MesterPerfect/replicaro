//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminal reports whether file is a console. A console build started from
// a terminal has one; the GUI build started from Explorer, the Start menu or
// a Run key has no stderr handle at all, and NUL isn't a console either.
func isTerminal(file *os.File) bool {
	connection, err := file.SyscallConn()
	if err != nil {
		return false
	}
	console := false
	_ = connection.Control(func(handle uintptr) {
		var mode uint32
		console = windows.GetConsoleMode(windows.Handle(handle), &mode) == nil
	})
	return console
}
