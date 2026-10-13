package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/local/replicaro/appdata"
)

// CapturedOutputPublisher receives the paths of the complete, unmodified
// stdout and stderr capture files after the process tree has been drained.
// It is for presentation only, and a logging failure must never affect the
// native result.
//
// Returning true hands both files over: the publisher (the operation log)
// appends them to the operation's log when the step is finalized and deletes
// them then, and Close leaves them alone. Until then the engine adapter that
// ran the command keeps reading them through OpenStdout/OpenStderr; every
// finalizer runs after that engine call has returned. Handing the files over
// instead of copying them saves one full write, read and fsync per stream.
// Returning false leaves them with the capture, and Close deletes them as
// usual. A file left behind by a crash before finalization is removed by
// CleanupCapturedOutput at the next start.
type CapturedOutputPublisher func(engine, kind, status, diagnostic, stdoutPath, stderrPath string) bool

type capturedOutputPublisherKey struct{}
type capturedOutputKindKey struct{}

func ContextWithCapturedOutputPublisher(ctx context.Context, publisher CapturedOutputPublisher) context.Context {
	if publisher == nil {
		return ctx
	}
	return context.WithValue(ctx, capturedOutputPublisherKey{}, publisher)
}

// ContextWithCapturedOutputKind identifies the exact native operation-log
// section for one command. It does not enable capture by itself.
func ContextWithCapturedOutputKind(ctx context.Context, kind string) context.Context {
	if kind == "" {
		return ctx
	}
	if existing, _ := ctx.Value(capturedOutputKindKey{}).(string); existing != "" {
		return ctx
	}
	return context.WithValue(ctx, capturedOutputKindKey{}, kind)
}

func capturedOutputPublication(ctx context.Context) (CapturedOutputPublisher, string) {
	publisher, _ := ctx.Value(capturedOutputPublisherKey{}).(CapturedOutputPublisher)
	kind, _ := ctx.Value(capturedOutputKindKey{}).(string)
	if publisher == nil || kind == "" {
		return nil, ""
	}
	return publisher, kind
}

// CapturedOutput owns two temporary, owner-local stream files. Callers parse
// through OpenStdout/OpenStderr and must Close the value when finished.
//
// The files are plain temporary files in the command-output folder under the
// app-data root: os.CreateTemp (mode 0600 and a unique name), a reopen by path
// for each reader, and os.Remove. On Windows the folder and the files inherit
// the application folder's protected DACL, so they get no ACL write of their
// own. There's deliberately no handle-relative open, no link, link-count,
// owner or mode re-check, and no per-call ACL write here. Those only resist
// someone with access to the computer swapping files in Replicaro's own
// folder, which Replicaro doesn't defend against. Don't add them back without
// a product decision.
//
// Readers open through appdata.OpenFileShareDelete so Close can still remove
// a capture file while a caller holds a reader on it. With Go's default
// Windows sharing that removal fails and the file stays until the next
// startup cleanup. The writer is always closed before anything removes the
// file, so os.CreateTemp's default sharing is enough for it.
type CapturedOutput struct {
	stdout *captureFile
	stderr *captureFile
	once   sync.Once
	// handedOff is set when a publisher took over both files; Close then
	// leaves them for the operation log to append and delete.
	handedOff atomic.Bool
}

type captureFile struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	writeErr error
	closed   bool
}

var beforeCaptureWrite func()

func capturedOutputDirectory() (string, error) { return appdata.Directory("command-output") }

func newCapturedOutput() (*CapturedOutput, error) {
	directory, err := capturedOutputDirectory()
	if err != nil {
		return nil, err
	}
	stdout, err := newCaptureFile(directory, ".stdout-*.tmp")
	if err != nil {
		return nil, err
	}
	stderr, err := newCaptureFile(directory, ".stderr-*.tmp")
	if err != nil {
		stdout.remove()
		return nil, err
	}
	return &CapturedOutput{stdout: stdout, stderr: stderr}, nil
}

// CleanupCapturedOutput removes abandoned files from the command-output
// directory once the application holds its single-instance guard. It only
// deletes leftovers: no capacity or disk-space checks, quotas, or log rotation.
func CleanupCapturedOutput() error {
	directory, err := capturedOutputDirectory()
	if err != nil {
		return err
	}
	return cleanupCapturedOutputDirectory(directory)
}

func cleanupCapturedOutputDirectory(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, entry := range entries {
		name := entry.Name()
		if (!strings.HasPrefix(name, ".stdout-") && !strings.HasPrefix(name, ".stderr-")) ||
			!strings.HasSuffix(name, ".tmp") || !entry.Type().IsRegular() {
			continue
		}
		if removeErr := os.Remove(filepath.Join(directory, name)); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, removeErr)
		}
	}
	return errors.Join(cleanupErrors...)
}

// CapturedOutputForTests constructs the same file-backed result without
// launching a process. It keeps engine test seams compatible while exercising
// the production reader and cleanup lifecycle.
func CapturedOutputForTests(stdoutValue, stderrValue []byte) (*CapturedOutput, error) {
	output, err := newCapturedOutput()
	if err != nil {
		return nil, err
	}
	_, _ = output.stdout.Write(stdoutValue)
	_, _ = output.stderr.Write(stderrValue)
	if err := output.finish(); err != nil {
		_ = output.Close()
		return nil, err
	}
	return output, nil
}

func newCaptureFile(directory, pattern string) (*captureFile, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return nil, err
	}
	return &captureFile{file: file, path: file.Name()}, nil
}

// Write deliberately reports complete consumption even after the local file
// fails. Pipe drainage must never stop because diagnostic capture failed; the
// recorded write error is returned separately as output-processing failure.
func (file *captureFile) Write(value []byte) (int, error) {
	file.mu.Lock()
	defer file.mu.Unlock()
	if beforeCaptureWrite != nil {
		beforeCaptureWrite()
	}
	if file.writeErr != nil || file.closed {
		return len(value), nil
	}
	if _, err := file.file.Write(value); err != nil {
		file.writeErr = err
	}
	return len(value), nil
}

func (file *captureFile) finish() error {
	file.mu.Lock()
	defer file.mu.Unlock()
	if file.closed {
		return file.writeErr
	}
	if file.writeErr == nil {
		file.writeErr = file.file.Sync()
	}
	if err := file.file.Close(); file.writeErr == nil {
		file.writeErr = err
	}
	file.closed = true
	return file.writeErr
}

func (file *captureFile) open() (*os.File, error) {
	file.mu.Lock()
	closed := file.closed
	path := file.path
	err := file.writeErr
	file.mu.Unlock()
	if !closed {
		return nil, fmt.Errorf("captured output is still being written")
	}
	if err != nil {
		return nil, err
	}
	return appdata.OpenFileShareDelete(filepath.Clean(path), os.O_RDONLY, 0)
}

// completePath returns the file's path once it is closed and was written
// without error, the state in which it may be handed to a publisher.
func (file *captureFile) completePath() (string, bool) {
	file.mu.Lock()
	defer file.mu.Unlock()
	return file.path, file.closed && file.writeErr == nil && file.path != ""
}

func (file *captureFile) remove() {
	file.mu.Lock()
	if !file.closed && file.file != nil {
		_ = file.file.Close()
		file.closed = true
	}
	path := file.path
	file.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
}

func (output *CapturedOutput) finish() error {
	return errorsJoin(output.stdout.finish(), output.stderr.finish())
}

// OpenStdout returns a fresh reader positioned at the start of the captured stdout.
func (output *CapturedOutput) OpenStdout() (*os.File, error) { return output.stdout.open() }

// OpenStderr returns a fresh reader positioned at the start of the captured stderr.
func (output *CapturedOutput) OpenStderr() (*os.File, error) { return output.stderr.open() }

func (output *CapturedOutput) publish(ctx context.Context, engine, status, diagnostic string) bool {
	publisher, kind := capturedOutputPublication(ctx)
	if publisher == nil {
		return false
	}
	// A capture that failed to write is never handed over: the log would
	// show a truncated stream as if it were complete.
	stdoutPath, stdoutOK := output.stdout.completePath()
	stderrPath, stderrOK := output.stderr.completePath()
	if !stdoutOK || !stderrOK {
		return false
	}
	if !publisher(engine, kind, status, diagnostic, stdoutPath, stderrPath) {
		return false
	}
	output.handedOff.Store(true)
	return true
}

// PublishForTests exercises the production publication boundary for engine
// test seams that construct captured output without launching a child process.
func (output *CapturedOutput) PublishForTests(ctx context.Context, engine, status, diagnostic string) bool {
	return output.publish(ctx, engine, status, diagnostic)
}

// Close removes both run-local capture files, unless a publisher took them
// over; the operation log deletes those after appending them.
func (output *CapturedOutput) Close() error {
	if output == nil {
		return nil
	}
	output.once.Do(func() {
		if output.handedOff.Load() {
			return
		}
		output.stdout.remove()
		output.stderr.remove()
	})
	return nil
}

func errorsJoin(values ...error) error {
	if err := errors.Join(values...); err != nil {
		return fmt.Errorf("captured command output: %w", err)
	}
	return nil
}
