//go:build !linux

package command

import "os/exec"

// Windows children already end with Replicaro through the job object's
// kill-on-close flag. macOS has no parent-death signal, so a quiet child there
// can outlive a crash until its next write to a closed pipe.
func endWithReplicaro(*exec.Cmd) {}

func lockStartingThread() func() { return func() {} }
