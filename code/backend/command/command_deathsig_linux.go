//go:build linux

package command

import (
	"os/exec"
	"runtime"
	"syscall"
)

// endWithReplicaro asks the kernel to SIGKILL the child when Replicaro ends.
// Process groups and sessions let Replicaro end a child only while Replicaro
// is still running; after a crash or a SIGKILL nothing would, and a quiet
// engine (waiting on a repository lock or a slow remote) keeps running and can
// still write to the repository. The signal reaches only the direct child;
// helpers the engine starts itself are left to end with the engine.
func endWithReplicaro(process *exec.Cmd) {
	process.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

// lockStartingThread keeps the calling goroutine on its OS thread until the
// returned function runs. Linux sends the parent-death signal when the thread
// that started the child exits, not when the process does, and the Go runtime
// ends a thread whenever a goroutine that locked it returns without unlocking.
// Holding the thread from Start until the child has been waited for means no
// other goroutine can take it over and end it while the child is still in use.
func lockStartingThread() func() {
	runtime.LockOSThread()
	return runtime.UnlockOSThread
}
