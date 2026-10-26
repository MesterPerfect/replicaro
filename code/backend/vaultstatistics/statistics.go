package vaultstatistics

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/database"
	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/models"
	"github.com/local/replicaro/rclone"
	"github.com/local/replicaro/repositoryadmission"
	"github.com/local/replicaro/runner"
	"github.com/local/replicaro/storageavailability"
	"github.com/local/replicaro/vaultlock"
	"github.com/local/replicaro/vaultprofile"
)

const (
	automaticCooldown  = 24 * time.Hour
	maximumOutputBytes = 1 << 20
	// measurementTimeLimit bounds one rclone size run. rclone has to list
	// every file in the vault, so the time depends on the number of files and
	// the storage's latency, not on terabytes: a large Kopia vault on a NAS
	// has hundreds of thousands of pack files and can take hours. The UI text
	// ui.protect.vaultSizeFailure.timedOut names this duration; change both
	// together.
	measurementTimeLimit = 24 * time.Hour
)

// Failure codes the status reports after a refresh fails. Each one names the
// step that failed and never the native error: Vault Size runs rclone with
// private output, so its messages are not kept. The UI turns the codes into
// translated text, so they are stable codes and not sentences.
// RefreshFailed covers everything the other codes don't.
const (
	RefreshFailed             = "vault_size_refresh_failed"
	FailureStorageUnreachable = "vault_size_storage_unreachable"
	FailureSettingsChanged    = "vault_size_settings_changed"
	FailurePreparation        = "vault_size_preparation_failed"
	FailureTimedOut           = "vault_size_timed_out"
	FailureMeasurement        = "vault_size_measurement_failed"
	FailureResultUnreadable   = "vault_size_result_unreadable"
	FailureSaveFailed         = "vault_size_save_failed"
)

// stepError tags an error with the failure code of the step that returned it.
type stepError struct {
	code string
	err  error
}

func (e *stepError) Error() string { return e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

func failAt(code string, err error) error { return &stepError{code: code, err: err} }

// failureCode picks the code for a failed refresh from the error's type alone.
// An identity mismatch is reported as a storage-unavailable error too, but it
// is not an unreachable storage, so it stays under RefreshFailed.
func failureCode(err error) string {
	var step *stepError
	if errors.As(err, &step) {
		return step.code
	}
	var unavailable *storageavailability.RepositoryStorageUnavailableError
	if errors.As(err, &unavailable) {
		if unavailable.ReasonCode == database.AvailabilityReasonIdentityMismatch {
			return RefreshFailed
		}
		return FailureStorageUnreachable
	}
	if errors.Is(err, storageavailability.ErrRepositoryStorageUnavailable) {
		return FailureStorageUnreachable
	}
	return RefreshFailed
}

var (
	materializeRclone = rclone.Materialize
	runRclone         = command.RunWithInputSecretsPrivateOutput
	measureVaultSize  = measure
	admitRepository   = repositoryadmission.AdmitUnderLock
	now               = time.Now
	// settingsCheckInterval is how often a running measurement checks that
	// the vault still exists with the storage settings it started with.
	settingsCheckInterval = 5 * time.Second
)

// errVaultSettingsChanged ends a running measurement whose vault was removed,
// relocated, or had its connector, path or credentials changed.
var errVaultSettingsChanged = errors.New("vault settings changed during the Vault Size measurement")

func SetRepositoryAdmissionForTests(next func(context.Context, *sql.DB, models.Repository) (models.Repository, error)) func() {
	previous := admitRepository
	admitRepository = next
	return func() { admitRepository = previous }
}

type coordinator struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	accept   bool
	wg       sync.WaitGroup
	running  map[string]bool
	pending  map[string]bool
	paused   map[string]bool
	failures map[string]string
	// slot lets one measurement run at a time across all vaults; the others
	// stay pending until it is free. Vault Size doesn't take a backup slot,
	// so this is its only concurrency limit. One slow vault (up to the 24-hour
	// time limit) holds up the others; that is accepted to keep listings from
	// piling up on the same disks and network.
	slot chan struct{}
}

func newCoordinator(ctx context.Context, cancel context.CancelFunc) *coordinator {
	return &coordinator{ctx: ctx, cancel: cancel, accept: true, running: map[string]bool{}, pending: map[string]bool{},
		paused: map[string]bool{}, failures: map[string]string{}, slot: make(chan struct{}, 1)}
}

var coordinators struct {
	sync.Mutex
	values map[*sql.DB]*coordinator
}

func init() { coordinators.values = map[*sql.DB]*coordinator{} }

func StartContext(parent context.Context, db *sql.DB) func(context.Context) error {
	coordinators.Lock()
	if old := coordinators.values[db]; old != nil {
		coordinators.Unlock()
		return old.stop
	}
	ctx, cancel := context.WithCancel(parent)
	c := newCoordinator(ctx, cancel)
	coordinators.values[db] = c
	coordinators.Unlock()
	return c.stop
}

func (c *coordinator) stop(ctx context.Context) error {
	c.mu.Lock()
	if c.accept {
		c.accept = false
		c.cancel()
	}
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func coordinatorFor(db *sql.DB) *coordinator {
	coordinators.Lock()
	defer coordinators.Unlock()
	if value := coordinators.values[db]; value != nil {
		return value
	}
	ctx, cancel := context.WithCancel(context.Background())
	value := newCoordinator(ctx, cancel)
	coordinators.values[db] = value
	return value
}

func Status(db *sql.DB, repositoryID string) (models.VaultSizeStatus, error) {
	return StatusWithReader(db, db, repositoryID)
}

// StatusWithReader keeps runtime state attached to the writer-owned coordinator
// while loading persisted fields through the query pool. Coordinators are keyed
// by *sql.DB, so using readDB for both jobs would create a second, empty
// coordinator and hide running, pending, paused, and failure state from the UI.
func StatusWithReader(coordinatorDB, readDB *sql.DB, repositoryID string) (models.VaultSizeStatus, error) {
	repo, err := database.GetRepository(readDB, repositoryID)
	if err != nil {
		return models.VaultSizeStatus{}, err
	}
	c := coordinatorFor(coordinatorDB)
	c.mu.Lock()
	running, pending, paused, failure := c.running[repositoryID], c.pending[repositoryID], c.paused[repositoryID], c.failures[repositoryID]
	c.mu.Unlock()
	return models.VaultSizeStatus{VaultSizeBytes: repo.VaultSizeBytes, VaultSizeMeasuredAt: repo.VaultSizeMeasuredAt,
		VaultSizeDirty: repo.VaultSizeDirty, Fresh: database.RepositoryVaultSizeFresh(repo, now()),
		Running: running, Pending: pending, Paused: paused && (running || pending), Failure: failure}, nil
}

func Prepare(db *sql.DB, repositoryID string, force bool) (models.VaultSizeStatus, error) {
	repo, err := database.GetRepository(db, repositoryID)
	if err != nil {
		return models.VaultSizeStatus{}, err
	}
	c := coordinatorFor(db)
	c.mu.Lock()
	if !c.accept {
		c.mu.Unlock()
		return models.VaultSizeStatus{}, runner.ErrAdmissionClosed
	}
	current := now()
	if c.running[repositoryID] || c.pending[repositoryID] {
		if force {
			if err := database.RecordVaultSizeAttempt(db, repositoryID, current); err != nil {
				c.mu.Unlock()
				return models.VaultSizeStatus{}, err
			}
		}
		c.mu.Unlock()
		return Status(db, repositoryID)
	}
	needed := !database.RepositoryVaultSizeFresh(repo, current)
	if !force && !needed {
		c.mu.Unlock()
		return Status(db, repositoryID)
	}
	if !force && repo.VaultSizeLastAttemptAt != "" {
		attempt, parseErr := time.Parse(time.RFC3339Nano, repo.VaultSizeLastAttemptAt)
		if parseErr == nil && !attempt.After(current) && current.Sub(attempt) < automaticCooldown {
			c.mu.Unlock()
			return Status(db, repositoryID)
		}
	}
	if err := database.RecordVaultSizeAttempt(db, repositoryID, current); err != nil {
		c.mu.Unlock()
		return models.VaultSizeStatus{}, err
	}
	c.pending[repositoryID] = true
	delete(c.failures, repositoryID)
	c.wg.Add(1)
	c.mu.Unlock()
	go c.run(db, repo)
	return Status(db, repositoryID)
}

func (c *coordinator) run(db *sql.DB, repo models.Repository) {
	defer c.wg.Done()
	var err error
	for c.ctx.Err() == nil {
		var yielded bool
		yielded, err = c.attempt(db, repo)
		// Admission runs under the low-priority vault lock, so a job that
		// needs the vault can interrupt it before the measurement starts.
		// Keep that refresh pending instead of dropping it into the automatic
		// cooldown.
		if yielded && c.ctx.Err() == nil {
			c.mu.Lock()
			delete(c.running, repo.ID)
			c.pending[repo.ID] = true
			c.paused[repo.ID] = true
			c.mu.Unlock()
			continue
		}
		break
	}
	c.mu.Lock()
	delete(c.running, repo.ID)
	delete(c.pending, repo.ID)
	delete(c.paused, repo.ID)
	if err != nil && c.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		c.failures[repo.ID] = failureCode(err)
		_ = database.LogWarning(db, "Vault Size refresh failed for vault "+repo.ID)
	}
	c.mu.Unlock()
}

// attempt runs one refresh. Admission (the vault's identity checks and its
// native config activation) and the measurement's preparation run under the
// low-priority shared vault lock, as every other vault reader's admission
// does. The lock is released right before rclone size starts and the listing
// runs without it: every backup takes the vault lock exclusively and cancels
// low-priority readers, so on a vault whose listing takes longer than the gap
// between its backups a locked measurement could never finish. Don't take the
// lock around rclone size again. A size measured while a backup writes is
// slightly off; the dirty count keeps such a vault marked for another refresh
// (see database.PublishVaultSize).
//
// Since the listing runs without the lock, removal, relocation and changes to
// the connector, path or credentials can't stop it by taking the lock.
// Instead the measurement checks the vault's saved settings every few seconds
// and stops when they change or the vault is gone, and the result is saved
// only if the settings still match in the same UPDATE. Without that check a
// removed vault could be listed for up to 24 hours, holding up every other
// vault's refresh.
func (c *coordinator) attempt(db *sql.DB, repo models.Repository) (yielded bool, err error) {
	workContext, unlock, lockErr := vaultlock.AcquireLowPrioritySharedContext(
		c.ctx,
		repo.ID,
		func(paused bool) {
			c.mu.Lock()
			if paused {
				c.paused[repo.ID] = true
			} else {
				delete(c.paused, repo.ID)
			}
			c.mu.Unlock()
		},
	)
	if lockErr != nil {
		return false, lockErr
	}
	locked := true
	releaseLock := func() {
		if locked {
			locked = false
			unlock()
		}
	}
	defer releaseLock()
	interrupted := func() bool {
		return locked && errors.Is(context.Cause(workContext), vaultlock.ErrLowPriorityYield)
	}
	// Wait for the measurement slot while holding only the low-priority lock:
	// a job that needs this vault meanwhile still interrupts the wait.
	select {
	case c.slot <- struct{}{}:
	case <-workContext.Done():
		return interrupted(), context.Cause(workContext)
	}
	defer func() { <-c.slot }()

	currentRepo, reloadErr := database.GetRepository(db, repo.ID)
	if errors.Is(reloadErr, sql.ErrNoRows) {
		return false, nil
	}
	if reloadErr != nil || currentRepo.Engine != repo.Engine || currentRepo.Connector != repo.Connector {
		authorityErr := fmt.Errorf("queued Vault Size authority changed before measurement")
		if reloadErr == nil {
			authorityErr = failAt(FailureSettingsChanged, authorityErr)
		}
		return false, errors.Join(reloadErr, authorityErr)
	}
	currentRepo, err = admitRepository(workContext, db, currentRepo)
	if err != nil {
		return interrupted(), err
	}
	measurement, err := database.BeginVaultSizeMeasurement(db, repo.ID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	delete(c.pending, repo.ID)
	c.running[repo.ID] = true
	c.mu.Unlock()

	sizeContext, cancelSize := context.WithCancelCause(c.ctx)
	defer cancelSize(nil)
	stopWatching := watchVaultSettings(sizeContext, cancelSize, db, measurement)
	bytes, err := measureVaultSize(workContext, sizeContext, currentRepo, releaseLock)
	stopWatching()
	if err != nil && interrupted() {
		return true, err
	}
	if errors.Is(context.Cause(sizeContext), errVaultSettingsChanged) {
		if _, missing := database.GetRepository(db, repo.ID); errors.Is(missing, sql.ErrNoRows) {
			// The vault was removed; there is nothing left to report on.
			return false, nil
		}
		return false, failAt(FailureSettingsChanged, errVaultSettingsChanged)
	}
	if err != nil {
		// Removing a vault also deletes its native config, so rclone size can
		// fail before the next settings check sees that the vault is gone.
		// As above, a vault that no longer exists has nothing to report, and
		// recording a failure would put a warning for it in the Activity log.
		if _, missing := database.GetRepository(db, repo.ID); errors.Is(missing, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if c.ctx.Err() != nil {
		return false, nil
	}
	if publishErr := database.PublishVaultSize(db, measurement, bytes, now()); publishErr != nil {
		switch {
		case errors.Is(publishErr, sql.ErrNoRows):
			return false, nil
		case errors.Is(publishErr, database.ErrVaultSizeSettingsChanged):
			return false, failAt(FailureSettingsChanged, publishErr)
		default:
			return false, failAt(FailureSaveFailed, publishErr)
		}
	}
	return false, nil
}

// watchVaultSettings cancels a running measurement once the vault is removed
// or its connector, location or connector options no longer match what the
// measurement started with. A failed read is retried at the next check.
func watchVaultSettings(ctx context.Context, cancel context.CancelCauseFunc, db *sql.DB, measurement database.VaultSizeMeasurement) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(settingsCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if current, err := database.VaultSizeMeasurementCurrent(db, measurement); err == nil && !current {
					cancel(errVaultSettingsChanged)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

// Measure measures a vault in one go, for callers that hold no vault lock.
func Measure(ctx context.Context, repo models.Repository) (int64, error) {
	return measure(ctx, ctx, repo, func() {})
}

// measure prepares the measurement with prepareContext (the vault-lock
// context), calls releaseLock right before rclone size starts, and runs rclone
// size and the config check after it with sizeContext, which a job taking the
// vault lock doesn't cancel.
func measure(prepareContext, sizeContext context.Context, repo models.Repository, releaseLock func()) (result int64, err error) {
	ctx := prepareContext
	base, err := vaultprofile.BaseRemoteForVault(repo)
	if err != nil {
		return 0, failAt(FailurePreparation, fmt.Errorf("prepare base vault root"))
	}
	// An Any Rclone Remote vault reads the user's own config file in place and
	// has no canonical config binding; its run environment is added after the
	// base settings below, so none of it is obscured again.
	var binding *engines.RcloneVaultConfigBinding
	var configPath string
	var rcloneRemoteEnv []string
	if repo.Connector == engines.RcloneRemoteConnector {
		run, runErr := engines.RcloneRemoteRunForRepository(repo)
		if runErr != nil {
			return 0, failAt(FailurePreparation, fmt.Errorf("prepare rclone remote: %w", runErr))
		}
		configPath, rcloneRemoteEnv = run.ConfigFile, run.Env
	} else {
		binding, err = engines.OpenExistingRcloneStatisticsConfigBinding(ctx, repo)
		if err != nil {
			return 0, failAt(FailurePreparation, fmt.Errorf("open canonical rclone configuration"))
		}
		defer func() { err = errors.Join(err, binding.Close()) }()
		configPath = binding.NativePath()
	}
	binary, err := materializeRclone()
	if err != nil {
		return 0, failAt(FailurePreparation, fmt.Errorf("prepare pinned rclone"))
	}
	if err := binding.Revalidate(ctx); err != nil {
		return 0, failAt(FailureSettingsChanged, fmt.Errorf("validate canonical rclone configuration"))
	}
	environment := append([]string(nil), base.Env...)
	for index, item := range environment {
		key, raw, ok := strings.Cut(item, "=")
		if !ok || key != "RCLONE_CONFIG_BASE_PASS" || raw == "" {
			continue
		}
		obscuredOutput, obscureErr := runRclone(ctx, binary,
			[]string{"obscure", "-", "--config", configPath}, nil, raw+"\n", time.Minute, "rclone")
		if obscureErr != nil {
			return 0, failAt(FailurePreparation, fmt.Errorf("prepare connector credential"))
		}
		obscured := strings.TrimSpace(obscuredOutput)
		if obscured == "" || strings.ContainsAny(obscured, "\r\n") {
			return 0, failAt(FailurePreparation, fmt.Errorf("prepare connector credential"))
		}
		environment[index] = key + "=" + obscured
	}
	environment = append(environment, rcloneRemoteEnv...)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	releaseLock()
	ctx = sizeContext
	launchContext := command.ContextWithBeforeProcess(ctx, func(check context.Context) error {
		if err := binding.Revalidate(check); err != nil {
			return failAt(FailureSettingsChanged, err)
		}
		return nil
	})
	output, nativeErr := runRclone(launchContext, binary,
		[]string{"size", base.Root, "--json", "--fast-list", "--config", configPath, "--log-level", "ERROR"},
		environment, "", measurementTimeLimit, "rclone")
	postErr := binding.Revalidate(context.WithoutCancel(ctx))
	if nativeErr != nil || postErr != nil {
		// Only the error's type picks the code; nativeErr is not wrapped, so
		// none of rclone's private output can reach the status or the log.
		return 0, failAt(nativeFailureCode(ctx, nativeErr), fmt.Errorf("native Vault Size measurement failed"))
	}
	bytes, err := ParseSizeOutput(output)
	if err != nil {
		return 0, failAt(FailureResultUnreadable, err)
	}
	return bytes, nil
}

// nativeFailureCode classifies a failed size command. With no command error,
// the configuration check after the command failed, so the settings changed
// while it ran. The check just before launch tags its own error, and storage
// errors keep their code. Any other failure before the process started (such
// as attaching it to its process tree) is not the storage's error, so it is
// unexpected. A deadline that isn't the caller's own is the command's time
// limit.
func nativeFailureCode(ctx context.Context, nativeErr error) string {
	if nativeErr == nil {
		return FailureSettingsChanged
	}
	var step *stepError
	var unavailable *storageavailability.RepositoryStorageUnavailableError
	if errors.As(nativeErr, &step) || errors.As(nativeErr, &unavailable) || errors.Is(nativeErr, storageavailability.ErrRepositoryStorageUnavailable) {
		return failureCode(nativeErr)
	}
	var beforeLaunch *command.PreProcessAdmissionError
	if errors.As(nativeErr, &beforeLaunch) {
		return RefreshFailed
	}
	if errors.Is(nativeErr, context.DeadlineExceeded) && ctx.Err() == nil {
		return FailureTimedOut
	}
	return FailureMeasurement
}

func ParseSizeOutput(output string) (int64, error) {
	if len(output) > maximumOutputBytes {
		return 0, fmt.Errorf("rclone size output is excessive")
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	value, err := readUnique(decoder)
	if err != nil {
		return 0, fmt.Errorf("invalid rclone size output")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return 0, fmt.Errorf("invalid trailing rclone size output")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("rclone size output is not an object")
	}
	bytes, ok := exactNonnegativeInt(object["bytes"])
	if !ok {
		return 0, fmt.Errorf("rclone size bytes are invalid")
	}
	if _, ok := exactNonnegativeInt(object["sizeless"]); !ok {
		return 0, fmt.Errorf("rclone size sizeless is invalid")
	}
	return bytes, nil
}

func exactNonnegativeInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(string(number), 10, 64)
	return parsed, err == nil && parsed >= 0
}

func readUnique(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate field")
			}
			child, err := readUnique(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		_, err = decoder.Token()
		return object, err
	case '[':
		array := []any{}
		for decoder.More() {
			child, err := readUnique(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		_, err = decoder.Token()
		return array, err
	default:
		return nil, fmt.Errorf("invalid delimiter")
	}
}
