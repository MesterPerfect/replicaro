package storageidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

const (
	DefaultMaxInput  = 64 << 10
	DefaultMaxOutput = 256 << 10
)

var ErrHelperStart = errors.New("storage helper process could not start")

// ErrHelperSlotsExhausted means a probe never got a helper slot because
// helpers that already timed out still hold slots while the OS finishes them.
// It says nothing about the storage this probe was asked about.
var ErrHelperSlotsExhausted = errors.New("storage helper slots are held by helpers that stopped responding")

// mountResponsiveWindow is how long after a helper on a mount answered that
// further helpers on that mount may run side by side. Outside it, helpers on
// one mount run one at a time, so a mount that stopped responding catches only
// one helper instead of every concurrent probe of it. The window only needs to
// cover the gap between probes in a burst, such as many backups starting at
// once, which keeps those probes running in parallel.
const mountResponsiveWindow = 2 * time.Second

// ServeHelper reads one probe request, performs it, and writes one response.
// Storage that cannot be observed is a normal response (access "missing",
// "denied", or "failed" with a step label and OS code). Only an invalid request
// or an oversized response is an error, which makes the helper exit non-zero
// so the parent reports a protocol failure instead of guessing.
func ServeHelper(reader io.Reader, writer io.Writer, maxInput, maxOutput int64) error {
	if maxInput <= 0 {
		maxInput = DefaultMaxInput
	}
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutput
	}
	requestBytes, err := readBounded(reader, maxInput)
	if err != nil {
		return err
	}
	var request HelperRequest
	if err := decodeStrict(requestBytes, &request); err != nil {
		return fmt.Errorf("decode storage helper request: %w", err)
	}
	response, err := ExecuteRequest(request)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > maxOutput {
		return fmt.Errorf("storage helper output exceeds limit")
	}
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("write storage helper response: %w", err)
	}
	return nil
}

// ProcessRunner launches one helper process per probe. A helper holds one of
// the live slots until the OS has reaped it, which bounds the number of helper
// processes even when some are stuck in a network filesystem call that the OS
// doesn't let them leave. Helpers are also counted per mount (the recorded
// mount point, or the path when none is recorded), and a mount with a
// timed-out helper that is still running gets no new helper until that one is
// gone. Together with mountResponsiveWindow, this normally keeps a mount that
// stops answering to one slot, so it can't stop the checks of every other
// drive or share.
type ProcessRunner struct {
	Executable string
	Args       []string
	Timeout    time.Duration
	MaxInput   int64
	MaxOutput  int64
	live       chan struct{}
	newProcess func([]byte, io.Writer, io.Writer) helperProcess

	mu sync.Mutex
	// mounts keeps one small entry per mount or path ever probed, which is
	// bounded by the storage the user has configured.
	mounts map[string]*mountHelpers
	// stuck counts helpers past their deadline that the OS hasn't reaped yet.
	stuck int
}

type mountHelpers struct {
	running         int // helpers started on this mount and not yet reaped
	stuck           int // of those, the ones past their deadline
	responsiveUntil time.Time
	// changed is closed and replaced whenever the counts or the window
	// change, to wake probes waiting for this mount.
	changed chan struct{}
}

// helperLaunch is one helper's place in the mount and slot accounting. Its
// fields are guarded by ProcessRunner.mu.
type helperLaunch struct {
	mount    *mountHelpers
	timedOut bool
	reaped   bool
}

// mountKey spells a Windows drive or share the way SameMountPoint compares
// them, so \\NAS\Photos, \\nas\photos\ and \\?\UNC\nas\photos share one entry.
func mountKey(request HelperRequest) string {
	if request.MountPoint != "" {
		return "mount:" + helperMountSpelling(request.MountPoint)
	}
	return "path:" + helperMountSpelling(request.Path)
}

func helperMountSpelling(value string) string {
	if windowsShapedMount(value) {
		return windowsMountKey(value)
	}
	return value
}

func NewProcessRunner(executable string, args []string, timeout time.Duration, maxConcurrent int) (*ProcessRunner, error) {
	if executable == "" || timeout <= 0 || maxConcurrent <= 0 {
		return nil, fmt.Errorf("helper executable, timeout, and concurrency are required")
	}
	runner := &ProcessRunner{
		Executable: executable, Args: append([]string(nil), args...), Timeout: timeout,
		MaxInput: DefaultMaxInput, MaxOutput: DefaultMaxOutput,
		live: make(chan struct{}, maxConcurrent),
	}
	runner.mounts = make(map[string]*mountHelpers)
	runner.newProcess = func(input []byte, stdout, stderr io.Writer) helperProcess {
		command := exec.Command(runner.Executable, runner.Args...)
		configureStorageHelperCommand(command)
		command.Stdin = bytes.NewReader(input)
		command.Stdout, command.Stderr = stdout, stderr
		return execHelperProcess{command: command}
	}
	return runner, nil
}

func (runner *ProcessRunner) Run(ctx context.Context, request HelperRequest) (HelperResponse, error) {
	if runner == nil || runner.live == nil || runner.newProcess == nil {
		return HelperResponse{}, fmt.Errorf("storage helper runner is not initialized")
	}
	if err := validateHelperRequest(request); err != nil {
		return HelperResponse{}, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return HelperResponse{}, err
	}
	maxInput := runner.MaxInput
	if maxInput <= 0 {
		maxInput = DefaultMaxInput
	}
	if int64(len(encoded)) > maxInput {
		return HelperResponse{}, fmt.Errorf("storage helper input exceeds limit")
	}
	deadlineContext, cancel := context.WithTimeout(ctx, runner.Timeout)
	defer cancel()
	if err := deadlineContext.Err(); err != nil {
		return HelperResponse{}, err
	}
	launch, err := runner.acquire(deadlineContext, mountKey(request))
	if err != nil {
		return HelperResponse{}, err
	}
	maxOutput := runner.MaxOutput
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutput
	}
	stdout := &boundedBuffer{limit: maxOutput}
	stderr := &boundedBuffer{limit: maxOutput}
	process := runner.newProcess(encoded, stdout, stderr)
	if process == nil {
		runner.release(launch, false)
		return HelperResponse{}, fmt.Errorf("create storage helper process")
	}
	if err := process.Start(); err != nil {
		runner.release(launch, false)
		return HelperResponse{}, fmt.Errorf("%w: %w", ErrHelperStart, err)
	}
	waited := make(chan error, 1)
	go func() {
		err := process.Wait()
		runner.release(launch, true)
		waited <- err
	}()
	select {
	case err := <-waited:
		if err != nil {
			if errors.Is(stdout.err, errLimitExceeded) || errors.Is(stderr.err, errLimitExceeded) {
				return HelperResponse{}, fmt.Errorf("storage helper output exceeds limit")
			}
			return HelperResponse{}, fmt.Errorf("storage helper failed")
		}
	case <-deadlineContext.Done():
		// Counted as timed out whether the deadline passed or the caller
		// cancelled: either way nothing waits for this helper any more, and
		// if the kill doesn't end it, its mount isn't answering.
		runner.markTimedOut(launch)
		_ = process.Kill()
		// Wait continues in the bounded live-helper goroutine. The caller
		// returns at its deadline, while the live slot remains held until the
		// child is eventually reaped. This bounds both callers and unreaped
		// processes even if an OS Wait implementation wedges after Kill.
		return HelperResponse{}, deadlineContext.Err()
	}
	if stdout.err != nil || stderr.err != nil {
		return HelperResponse{}, fmt.Errorf("storage helper output exceeds limit")
	}
	var response HelperResponse
	if err := decodeStrict(stdout.Bytes(), &response); err != nil {
		return HelperResponse{}, fmt.Errorf("decode storage helper response: %w", err)
	}
	if err := ValidateHelperResponse(request, response); err != nil {
		return HelperResponse{}, err
	}
	return response, nil
}

// acquire waits until a helper may start for the mount and then takes a live
// slot. Waiting for the mount ends with the context's error, because only that
// mount's own helper is holding things up; the storage behind it may be the
// problem. Waiting for a slot while timed-out helpers hold slots ends with
// ErrHelperSlotsExhausted instead, because the stuck storage is elsewhere.
func (runner *ProcessRunner) acquire(ctx context.Context, key string) (*helperLaunch, error) {
	for {
		if err := runner.waitForMount(ctx, key); err != nil {
			return nil, err
		}
		select {
		case runner.live <- struct{}{}:
		case <-ctx.Done():
			runner.mu.Lock()
			stuckElsewhere := runner.stuck > runner.mountLocked(key).stuck
			runner.mu.Unlock()
			if stuckElsewhere && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ErrHelperSlotsExhausted
			}
			return nil, ctx.Err()
		}
		// Another probe of the same mount may have started, or a helper there
		// may have timed out, while this one waited for a slot.
		runner.mu.Lock()
		mount := runner.mountLocked(key)
		if mountAcceptsHelperLocked(mount, time.Now()) {
			mount.running++
			runner.mu.Unlock()
			return &helperLaunch{mount: mount}, nil
		}
		runner.mu.Unlock()
		<-runner.live
	}
}

func (runner *ProcessRunner) waitForMount(ctx context.Context, key string) error {
	for {
		runner.mu.Lock()
		mount := runner.mountLocked(key)
		if mountAcceptsHelperLocked(mount, time.Now()) {
			runner.mu.Unlock()
			return nil
		}
		// Only a helper on this mount finishing, timing out or being reaped
		// can let this probe start; the window closing never does.
		changed := mount.changed
		runner.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func mountAcceptsHelperLocked(mount *mountHelpers, now time.Time) bool {
	return mount.stuck == 0 && (mount.running == 0 || now.Before(mount.responsiveUntil))
}

func (runner *ProcessRunner) mountLocked(key string) *mountHelpers {
	mount := runner.mounts[key]
	if mount == nil {
		mount = &mountHelpers{changed: make(chan struct{})}
		runner.mounts[key] = mount
	}
	return mount
}

func (mount *mountHelpers) signalLocked() {
	close(mount.changed)
	mount.changed = make(chan struct{})
}

func (runner *ProcessRunner) markTimedOut(launch *helperLaunch) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if launch.reaped || launch.timedOut {
		return
	}
	launch.timedOut = true
	launch.mount.stuck++
	launch.mount.responsiveUntil = time.Time{}
	runner.stuck++
	launch.mount.signalLocked()
}

// release runs once the helper is reaped, or right away when it never
// started, and frees its mount place and live slot. exited says the helper ran
// and exited; one that did so before its deadline shows the mount answers.
func (runner *ProcessRunner) release(launch *helperLaunch, exited bool) {
	runner.mu.Lock()
	launch.reaped = true
	launch.mount.running--
	if launch.timedOut {
		launch.mount.stuck--
		runner.stuck--
	} else if exited {
		launch.mount.responsiveUntil = time.Now().Add(mountResponsiveWindow)
	}
	launch.mount.signalLocked()
	runner.mu.Unlock()
	<-runner.live
}

type helperProcess interface {
	Start() error
	Wait() error
	Kill() error
}

type execHelperProcess struct {
	command *exec.Cmd
}

func (process execHelperProcess) Start() error { return process.command.Start() }
func (process execHelperProcess) Wait() error  { return process.command.Wait() }
func (process execHelperProcess) Kill() error  { return process.command.Process.Kill() }

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("storage helper input exceeds limit")
	}
	return data, nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

var errLimitExceeded = errors.New("bounded output exceeded")

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
	err    error
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if buffer.err != nil {
		return 0, buffer.err
	}
	remaining := buffer.limit - int64(buffer.buffer.Len())
	if remaining <= 0 || int64(len(value)) > remaining {
		if remaining > 0 {
			_, _ = buffer.buffer.Write(value[:remaining])
		}
		buffer.err = errLimitExceeded
		if remaining < 0 {
			remaining = 0
		}
		return int(remaining), buffer.err
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedBuffer) Bytes() []byte { return buffer.buffer.Bytes() }
