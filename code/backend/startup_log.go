package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local/replicaro/appdata"
	"github.com/local/replicaro/desktop"
	"github.com/local/replicaro/instanceguard"
)

// The startup log keeps a copy of everything the standard logger prints in a
// file. Desktop launches on Windows and macOS have nowhere for stderr to go
// (Windows builds have no console, and launchd discards a login item's
// output), so without the file a failed start leaves no trace. Linux writes
// the same file so support can ask for it on every platform.
//
// Like the owner-only operation logs, the file isn't redacted: it can hold
// native excerpts with file paths in them. Only the support report redacts.
const (
	startupLogName = "replicaro-startup.log"
	// startupLogLimit keeps the file small. Logging continues after startup
	// for as long as the process runs, so without a limit a long run would
	// keep growing it. Past the limit the file is moved to
	// replicaro-startup.log.1, replacing the older one, and a new one starts.
	startupLogLimit = 1 << 20
)

var (
	// startupLogPath is where this process's log file is, or empty when no
	// file could be opened. run sets it; main names it in the failure notice.
	startupLogPath string
	// activeStartupLog is the file behind startupLogPath, kept so tests that
	// call run can close it again.
	activeStartupLog *startupLog
	// headlessStart is set when run was started in headless service mode.
	// Desktop services can still carry a DISPLAY, so main checks this rather
	// than the environment before it shows the failure notice.
	headlessStart bool
	// serviceStarted is set once desktop.Run hands control to the service.
	// An error after that is a runtime or shutdown failure, not a failed
	// start, so main doesn't show the startup failure notice for it.
	serviceStarted atomic.Bool
	// showStartupFailure shows the failure notice through the desktop
	// integration of the platform.
	showStartupFailure = desktop.ShowStartupFailure
	// renameStartupLog moves the full file aside. It's a variable so tests
	// can make the move fail.
	renameStartupLog = os.Rename
)

type startupLog struct {
	mu    sync.Mutex
	path  string
	file  *os.File
	size  int64
	limit int64
	// rotateAt is the size at which the file is next moved aside. It's the
	// limit, except after a move failed; see rotate.
	rotateAt int64
	// crashOutput is set for the process's own log, which also receives Go
	// runtime crash output.
	crashOutput bool
}

// startStartupLog sends the standard logger to stderr and the startup log
// file, and returns the file's path, or "" when no file could be opened. It
// first tries the data folder. When the data folder is the problem (it can't
// be created, or the file can't be written there), the log goes to a fallback
// file instead, because that is the start that most needs a log.
//
// run doesn't call this for the container package: Docker already keeps
// stderr, and the state volume stays as it was.
func startStartupLog() string {
	startupLog := openStartupLog(appdata.File, startupLogFallbackFile, startupLogLimit)
	if startupLog == nil {
		return ""
	}
	startupLog.mu.Lock()
	startupLog.crashOutput = true
	startupLog.copyCrashOutput()
	startupLog.mu.Unlock()
	activeStartupLog = startupLog
	// The file comes first because io.MultiWriter stops at the first writer
	// that fails. In the Windows GUI build there's no console, so every write
	// to stderr fails; startupLog.Write never does, so the file gets every
	// line and stderr still gets them wherever it exists.
	log.SetOutput(io.MultiWriter(startupLog, os.Stderr))
	return startupLog.path
}

// startupLogFallbackFile is in ~/Library/Logs/Replicaro on macOS, where
// Console shows it, and in the user's temporary folder on Windows. Linux
// prefers $XDG_RUNTIME_DIR, which belongs to the user. Without it the file
// goes in /tmp, which every user shares, so the name carries the uid to keep
// users from writing into each other's file.
func startupLogFallbackFile() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Logs", "Replicaro", startupLogName), nil
	case "linux":
		if runtimeDirectory := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(runtimeDirectory) {
			return filepath.Join(runtimeDirectory, startupLogName), nil
		}
		return filepath.Join(os.TempDir(), fmt.Sprintf("replicaro-startup-%d.log", os.Getuid())), nil
	}
	return filepath.Join(os.TempDir(), startupLogName), nil
}

// openStartupLog opens the log at dataFile(startupLogName), or at fallback()
// when that fails, and returns nil when neither works. A fallback file
// records why the data folder couldn't be used.
func openStartupLog(dataFile func(string) (string, error), fallback func() (string, error), limit int64) *startupLog {
	path, primaryErr := dataFile(startupLogName)
	if primaryErr == nil {
		startupLog, err := openStartupLogAt(path, limit)
		if err == nil {
			startupLog.header("")
			return startupLog
		}
		primaryErr = err
	}
	fallbackPath, err := fallback()
	if err == nil {
		err = os.MkdirAll(filepath.Dir(fallbackPath), 0o700)
	}
	if err != nil {
		return nil
	}
	startupLog, err := openStartupLogAt(fallbackPath, limit)
	if err != nil {
		return nil
	}
	startupLog.header(fmt.Sprintf("the data folder could not be used for this log: %v", primaryErr))
	return startupLog
}

func openStartupLogAt(path string, limit int64) (*startupLog, error) {
	startupLog := &startupLog{path: path, limit: limit, rotateAt: limit}
	if err := startupLog.open(); err != nil {
		return nil, err
	}
	return startupLog, nil
}

// open appends to the file, creating it owner-only. The handle allows
// deletion so a second launch, which appends to the same file, can still
// move it aside on Windows while this process has it open.
func (startupLog *startupLog) open() error {
	file, err := appdata.OpenFileShareDelete(startupLog.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	startupLog.file, startupLog.size = file, info.Size()
	return nil
}

// header writes a line that separates this process from earlier ones in the
// file. It goes to the file only, so stderr reads the same as before.
func (startupLog *startupLog) header(note string) {
	line := fmt.Sprintf("%s Replicaro process %d started", time.Now().Format("2006/01/02 15:04:05"), os.Getpid())
	if note != "" {
		line += "; " + note
	}
	_, _ = startupLog.Write([]byte(line + "\n"))
}

// Write never fails, so io.MultiWriter still passes every line on to stderr.
// When the file can't be written or reopened, the file is dropped and logging
// carries on through stderr alone.
func (startupLog *startupLog) Write(data []byte) (int, error) {
	startupLog.mu.Lock()
	defer startupLog.mu.Unlock()
	if startupLog.file != nil && startupLog.size > 0 && startupLog.size+int64(len(data)) > startupLog.rotateAt {
		startupLog.rotate()
	}
	if startupLog.file == nil {
		return len(data), nil
	}
	written, err := startupLog.file.Write(data)
	startupLog.size += int64(written)
	if err != nil {
		_ = startupLog.file.Close()
		startupLog.file = nil
	}
	return len(data), nil
}

// rotate moves the file to .1 and starts a new one. When the move fails
// (another program may have the old .1 open on Windows, say), the current
// file is reopened and logging goes on in it. The next move is tried once
// the file has grown by another limit's worth, not on every line, so a move
// that keeps failing doesn't cost a close, a rename and an open per line.
func (startupLog *startupLog) rotate() {
	_ = startupLog.file.Close()
	startupLog.file = nil
	renameErr := renameStartupLog(startupLog.path, startupLog.path+".1")
	if err := startupLog.open(); err != nil {
		return
	}
	startupLog.rotateAt = startupLog.limit
	if renameErr != nil {
		startupLog.rotateAt = startupLog.size + startupLog.limit
	}
	startupLog.copyCrashOutput()
}

// copyCrashOutput makes the Go runtime also write an unhandled panic or other
// fatal error to the file, which matters most where stderr goes nowhere.
// SetCrashOutput keeps its own duplicate of the descriptor, so after a move
// it's pointed at the new file; otherwise crashes would land in .1. If the
// file is later dropped, crashes keep going to the last file that worked.
func (startupLog *startupLog) copyCrashOutput() {
	if startupLog.crashOutput && startupLog.file != nil {
		_ = debug.SetCrashOutput(startupLog.file, debug.CrashOptions{})
	}
}

// finishRun logs what run returned and returns the exit code. For a failed
// start it also shows the error to the user once, through show. There's no
// notice when:
//   - the service had already started, because a later error isn't a failed
//     start;
//   - this was a second launch that only opens (or fails to open) the running
//     instance's page, since the running instance is fine;
//   - Replicaro runs in headless service mode, where nobody sits at a
//     desktop to see it;
//   - stderr is captured on Windows or macOS (see stderrCaptured);
//   - the user declined to repair a damaged installation in the dialog that
//     just asked.
func finishRun(err error, started, headless, stderrCaptured bool, logPath string, show func(string)) int {
	if err == nil {
		return 0
	}
	log.Print(err)
	if !started && !headless && !stderrCaptured && !errors.Is(err, instanceguard.ErrAlreadyRunning) &&
		!errors.Is(err, errRepairDeclined) {
		show(startupFailureMessage(err, logPath))
	}
	return 1
}

func startupFailureMessage(err error, logPath string) string {
	// The repair message already says that Replicaro can't start and what to
	// do, so it's shown as it is.
	if errors.Is(err, errRepairNeeded) {
		return err.Error()
	}
	reason := strings.TrimRight(strings.TrimSpace(err.Error()), ".")
	if logPath == "" {
		return "Replicaro couldn't start: " + reason + "."
	}
	return "Replicaro couldn't start: " + reason + ". Details are in " + logPath + "."
}

// stderrCaptured reports whether stderr goes to a file, a pipe or a terminal
// on Windows or macOS. The notice there is a modal dialog: whoever started
// Replicaro from a terminal or with stderr redirected reads the error there,
// and a dialog would only leave their shell or a scripted start waiting for a
// click. A desktop start gets the notice: launchd and Finder hand an app
// /dev/null, and a start from Explorer, the Start menu or a Run key has no
// stderr at all. On Linux the notice is a desktop notification, which blocks
// nothing, and graphical sessions often send every app's stderr to the
// journal or to ~/.xsession-errors, where nobody looks. So on Linux this is
// always false and the notification is shown.
func stderrCaptured() bool {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return false
	}
	if isTerminal(os.Stderr) {
		return true
	}
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() || info.Mode()&os.ModeNamedPipe != 0
}
