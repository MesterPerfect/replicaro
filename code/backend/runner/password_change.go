package runner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/local/replicaro/database"
	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/locale"
	"github.com/local/replicaro/models"
	"github.com/local/replicaro/notifications"
	"github.com/local/replicaro/profilesync"
	"github.com/local/replicaro/repositoryadmission"
	"github.com/local/replicaro/vaultlock"
	"github.com/local/replicaro/vaultprofile"
)

var vaultPasswordQuietPeriod = 30 * time.Second

// A preparation restart after a failure (a fence write, or a fenced inventory
// capture before the quiet period, after it or at staging, that a fresh
// capture doesn't reproduce, or a pending object still listed after its
// cleanup) waits 1, 2, 4, 8 and then 16 seconds, about half a minute
// in all, which is about one quiet period: enough to ride out a brief storage
// hiccup without holding the vault for long when the failure persists. After
// the fifth restart the change rolls back instead. A restart because the
// inventory changed across the quiet period is neither delayed nor counted.
const (
	vaultPasswordPrepareRestartLimit   = 5
	vaultPasswordPrepareRestartBackoff = time.Second
)

var waitVaultPasswordPrepareRestart = func(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var errPasswordChangePendingReappeared = errors.New("pending protected recovery metadata reappeared after cleanup")

var recordVaultPasswordNativeResult = database.RecordVaultPasswordNativeResult
var loadVaultPasswordChangeAfterNativeResult = database.VaultPasswordChange
var recoverVaultPasswordChange = RecoverVaultPasswordChange
var vaultPasswordChangeFault = func(string) error { return nil }
var prepareVaultPasswordChange = preparePasswordChange
var captureVaultPasswordKopiaFormat = captureKopiaFormatBeforeLaunch
var resolveVaultPasswordEngine = engines.Resolve
var runNativeVaultPasswordChange = engines.ChangeRepositoryPassword
var probeVaultPassword = engines.ProbeRepositoryPassword
var publishVaultPasswordTree = func(ctx context.Context, store vaultprofile.Store, inventory vaultprofile.PasswordRotationInventory) error {
	return store.PublishPasswordRotatedTree(ctx, inventory)
}
var cleanupVaultPasswordStage = vaultprofile.CleanupPasswordRotationStage
var loadVaultPasswordStage = vaultprofile.LoadPasswordRotationInventory
var captureVaultPasswordRollbackInventory = func(ctx context.Context, store vaultprofile.Store, operationUUID string) (vaultprofile.PasswordRotationInventory, error) {
	return store.CapturePasswordRotationInventory(ctx, operationUUID, false)
}
var deleteVaultPasswordRollbackPending = func(ctx context.Context, store vaultprofile.Store, inventory vaultprofile.PasswordRotationInventory) error {
	return store.DeletePasswordChangeOperationPending(ctx, inventory)
}
var removeVaultPasswordChangeFence = func(ctx context.Context, repo models.Repository, inventory vaultprofile.PasswordRotationInventory) error {
	store := (vaultprofile.Store{Repository: repo})
	return store.SetPasswordChangeFence(ctx, inventory, false)
}
var assertVaultPasswordChangeAuthority = func(ctx context.Context, store vaultprofile.Store, repo models.Repository,
	operation database.VaultPasswordChangeOperation, allowUnfenced, requireProfileFence bool,
) error {
	return store.AssertPasswordChangeAuthority(ctx, repo.ClientUUID, repo.ProfileUUID, repo.AttachmentGeneration,
		operation.OperationUUID, allowUnfenced, requireProfileFence)
}
var admitPasswordChangeRecoveryUnderLock = repositoryadmission.AdmitPasswordChangeRecoveryUnderLock

// SetPasswordChangeRecoveryAdmissionForTests replaces the admission a
// password change Retry runs under the vault lock, with its phase record
// already saved. Tests of the tracked worker in other packages use it to hold
// a Retry at exactly that point.
func SetPasswordChangeRecoveryAdmissionForTests(next func(context.Context, *sql.DB, models.Repository, repositoryadmission.PasswordChangeRecoveryOptions) (models.Repository, error)) func() {
	previous := admitPasswordChangeRecoveryUnderLock
	admitPasswordChangeRecoveryUnderLock = next
	return func() { admitPasswordChangeRecoveryUnderLock = previous }
}

var abandonConclusivePreMutationPasswordChange = func(db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation) error {
	if operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation) {
		return database.AbandonRejectedBeforeMutationVaultPasswordChange(db, repo.ID)
	}
	return database.AbandonConclusiveUnstartedVaultPasswordChange(db, repo.ID)
}

type VaultPasswordChangeResult struct {
	RepositoryID   string                       `json:"repositoryId"`
	OperationUUID  string                       `json:"operationUUID"`
	Phase          string                       `json:"phase"`
	Native         engines.PasswordChangeResult `json:"native"`
	SidecarStatus  string                       `json:"sidecarStatus"`
	CleanupPending bool                         `json:"cleanupPending"`
	Message        string                       `json:"message"`
	ResticKeyTruth string                       `json:"resticKeyTruth,omitempty"`
	// Recovering is set by the status reads while startup recovery holds the
	// vault for this change, so the vault card can show the change as still
	// finishing instead of offering a Retry that would be refused.
	Recovering bool `json:"recovering,omitempty"`
}

func nativePasswordResultTruth(operation database.VaultPasswordChangeOperation) string {
	if operation.NativeStatus == "" {
		return "unresolved"
	}
	return operation.NativeStatus
}

func verifiedCandidateNativeSummary(operation database.VaultPasswordChangeOperation) string {
	if operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation) {
		return "Restic rejected the selected-key password change before mutation; the pending credential verified separately"
	}
	return fmt.Sprintf("the pending credential verified while native password-mutation truth remains %s", nativePasswordResultTruth(operation))
}

func passwordChangeResult(repo models.Repository, operation database.VaultPasswordChangeOperation) VaultPasswordChangeResult {
	result := VaultPasswordChangeResult{RepositoryID: repo.ID, OperationUUID: operation.OperationUUID,
		Phase: operation.Phase, SidecarStatus: "pending",
		Native: engines.PasswordChangeResult{Engine: repo.Engine, Status: engines.RequestedOperationStatus(operation.NativeStatus),
			Output: operation.NativeOutput, MutationDisposition: engines.PasswordMutationDisposition(operation.NativeMutationDisposition)}}
	if operation.NativeStatus == "succeeded" || operation.NativeStatus == "failed" || operation.NativeStatus == "interrupted" {
		result.Native.ProcessStarted = true
	}
	nativeSucceeded := operation.NativeStatus == "succeeded"
	nativeTruth := nativePasswordResultTruth(operation)
	if operation.Phase == "cleanup_pending" && nativeSucceeded {
		result.SidecarStatus, result.CleanupPending = "succeeded", true
		result.Message = "The native vault password and protected recovery metadata changed successfully; local residue cleanup is pending."
	} else if operation.Phase == "cleanup_pending" {
		result.SidecarStatus, result.CleanupPending = "succeeded", true
		result.Message = fmt.Sprintf("The pending vault password verified and protected recovery metadata was updated; local residue cleanup is pending. The recorded native result remains %s.", nativeTruth)
	} else if operation.Phase == "publishing" && nativeSucceeded {
		result.Message = "The native vault password changed, but protected recovery metadata publication is incomplete and must recover forward."
	} else if operation.Phase == "publishing" {
		result.Message = fmt.Sprintf("The pending vault password verified, but protected recovery metadata publication is incomplete. The recorded native result remains %s.", nativeTruth)
	} else {
		result.Message = "Vault-password change recovery is in progress."
	}
	if repo.Engine == engines.ResticID {
		switch {
		case operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation):
			result.ResticKeyTruth = "Restic rejected the selected-key password change because the repository was locked before mutation. The selected key was not changed."
		case operation.NativeStatus == "succeeded":
			result.ResticKeyTruth = "Restic changed the selected key. Other Restic keys were not removed and may still accept an older password."
		default:
			result.ResticKeyTruth = "Whether Restic changed the selected key is unresolved. Other Restic keys may still accept an older password."
		}
	}
	return result
}

func runLocalNativePasswordChangeResult(repo models.Repository, operation database.VaultPasswordChangeOperation, native engines.PasswordChangeResult, disposition string) VaultPasswordChangeResult {
	runLocal := operation
	runLocal.NativeStatus = string(native.Status)
	runLocal.NativeMutationDisposition = disposition
	runLocal.NativeOutput = native.Output
	result := passwordChangeResult(repo, runLocal)
	result.Native = native
	return result
}

func persistRunLocalNativePasswordResult(db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native engines.PasswordChangeResult, nativeErr error) (database.VaultPasswordChangeOperation, VaultPasswordChangeResult, error) {
	status := string(native.Status)
	if status != "not_started" && status != "succeeded" && status != "failed" && status != "interrupted" {
		return operation, passwordChangeResult(repo, operation), fmt.Errorf("native vault-password result is unresolved; explicit retry is required")
	}
	safeError := ""
	if nativeErr != nil {
		safeError = nativeErr.Error()
	}
	disposition := string(native.MutationDisposition)
	if disposition == "" {
		disposition = string(engines.PasswordMutationUnknown)
	}
	if err := recordVaultPasswordNativeResult(db, repo.ID, status, disposition, native.Output, safeError); err != nil {
		return operation, runLocalNativePasswordChangeResult(repo, operation, native, disposition), fmt.Errorf("persist native vault-password result: %w", err)
	}
	updated, err := loadVaultPasswordChangeAfterNativeResult(db, repo.ID)
	if err != nil {
		return operation, runLocalNativePasswordChangeResult(repo, operation, native, disposition), err
	}
	return updated, passwordChangeResult(repo, updated), nil
}

// VaultPasswordChangeStatus reports only same-installation durable recovery
// state. It performs no repository access and discloses no remote owner facts.
func VaultPasswordChangeStatus(db *sql.DB, repositoryID string) (VaultPasswordChangeResult, error) {
	repo, err := database.GetRepository(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	operation, err := database.VaultPasswordChange(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	return passwordChangeStatusResult(repo, operation), nil
}

// passwordChangeStatusResult is what the status reads report for one change.
// A change still in native_started also says why its last attempt stopped
// (storage unavailable, a live Restic lock, an earlier command still running
// and so on), since the vault card has no other way to show why the change
// still waits for a Retry. That replaces the "recovery is in progress"
// wording, which would contradict it. While startup recovery is working on
// the change, the reason is about to be replaced, so it is left out.
func passwordChangeStatusResult(repo models.Repository, operation database.VaultPasswordChangeOperation) VaultPasswordChangeResult {
	result := passwordChangeResult(repo, operation)
	result.Recovering = StartupPasswordRecoveryRunning(repo.ID)
	if operation.Phase == "native_started" && operation.LastError != "" && !result.Recovering {
		reason := strings.TrimSpace(operation.LastError)
		if !strings.HasSuffix(reason, ".") {
			reason += "."
		}
		result.Message = "The vault-password change has not finished. The last attempt stopped: " + reason
	}
	return result
}

// recordNativeStartedStopReason saves why an attempt at a native_started
// change stopped, so the status reads can show it. A failed or unstarted
// command's error stays the recorded error instead: a later rollback reports
// it as the engine's own result. An attempt
// cancelled because the app is stopping saves nothing either: "context
// canceled" explains nothing, the next start's recovery replaces it anyway,
// and a shutdown leaves the phase record as it found it. Running out of time
// (startup recovery's bound) is a reason and is saved.
func recordNativeStartedStopReason(ctx context.Context, db *sql.DB, repositoryID string, operation database.VaultPasswordChangeOperation, err error) {
	if operation.Phase != "native_started" || operation.NativeStatus == "failed" || operation.NativeStatus == "not_started" ||
		errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	_ = database.RecordVaultPasswordChangeError(db, repositoryID, err.Error())
}

// VaultPasswordChangeStatuses reports every vault's unfinished password
// change, as VaultPasswordChangeStatus does for one vault, so the vault list
// can rebuild its cards with one request instead of one per vault. A change
// whose vault is removed between the two reads is left out.
func VaultPasswordChangeStatuses(db *sql.DB) ([]VaultPasswordChangeResult, error) {
	operations, err := database.ListVaultPasswordChanges(db)
	if err != nil {
		return nil, err
	}
	results := make([]VaultPasswordChangeResult, 0, len(operations))
	for _, operation := range operations {
		repo, err := database.GetRepository(db, operation.RepositoryID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		results = append(results, passwordChangeStatusResult(repo, operation))
	}
	return results, nil
}

// VaultLock takes a vault's exclusive lock for a password change and returns
// its release. The tracked background operation passes one that waits for a
// busy vault while its record stays queued, and that closes the operation's
// cancel once the lock is held: from there the change cannot be stopped.
// Startup recovery takes the lock with TryVaultLock before anything else runs
// and passes one that hands over the lock it already holds.
type VaultLock func(ctx context.Context, repositoryID string) (func(), error)

// TryVaultLock refuses a busy vault instead of waiting for it. Startup
// recovery takes its locks before any worker or request exists, so nothing
// else should hold them, and its bounded attempt must not sit behind one that
// does.
func TryVaultLock(ctx context.Context, repositoryID string) (func(), error) {
	unlock, ok, err := vaultlock.YieldLowPriorityAndTryExclusiveContext(ctx, repositoryID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("vault is busy with another operation")
	}
	return unlock, nil
}

// ValidateVaultPasswordChangeRequest holds the checks a password change
// request makes before its operation is queued; none of them needs the vault
// lock. ChangeVaultPassword repeats them in the worker.
func ValidateVaultPasswordChangeRequest(db *sql.DB, repositoryID, candidate string) error {
	if err := models.ValidateVaultPassword(candidate); err != nil {
		return err
	}
	repo, err := database.GetRepository(db, repositoryID)
	if err != nil {
		return err
	}
	if operation, err := database.VaultPasswordChange(db, repositoryID); err == nil {
		if operation.Phase == "cleanup_pending" || repo.PendingPassphrase == "" || candidate != repo.PendingPassphrase {
			return errDifferentVaultPasswordChangePending
		}
		// Submitting the same pending candidate again resumes that change.
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if candidate == repo.Passphrase {
		return errUnchangedVaultPassword
	}
	return database.ValidateRepositoryMutationAdmission(db, repositoryID)
}

var (
	errDifferentVaultPasswordChangePending = errors.New("a different vault-password change is already pending; use Retry to recover it")
	errUnchangedVaultPassword              = errors.New("new vault password must differ from the current password")
)

func ChangeVaultPassword(ctx context.Context, db *sql.DB, repositoryID, candidate string, lock VaultLock) (VaultPasswordChangeResult, error) {
	if err := models.ValidateVaultPassword(candidate); err != nil {
		return VaultPasswordChangeResult{}, err
	}
	if operation, err := database.VaultPasswordChange(db, repositoryID); err == nil {
		repo, loadErr := database.GetRepository(db, repositoryID)
		if loadErr != nil {
			return VaultPasswordChangeResult{}, loadErr
		}
		if operation.Phase == "cleanup_pending" || repo.PendingPassphrase == "" || candidate != repo.PendingPassphrase {
			return passwordChangeResult(repo, operation), errDifferentVaultPasswordChangePending
		}
		return recoverVaultPasswordChange(ctx, db, repositoryID, lock)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return VaultPasswordChangeResult{}, err
	}
	repo, err := database.GetRepository(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	if candidate == repo.Passphrase {
		return VaultPasswordChangeResult{}, errUnchangedVaultPassword
	}
	unlock, err := lock(ctx, repo.ID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	defer unlock()
	// This installation's own pending profile publication is resolved first,
	// under the same lock the change then keeps, so nothing can queue another
	// one in between.
	if _, err := database.VaultProfileSyncState(db, repositoryID); err == nil {
		if err := profilesync.SyncRepositoryUnderLock(ctx, db, repositoryID); err != nil {
			return VaultPasswordChangeResult{}, fmt.Errorf("resolve pending local recovery-profile publication before password change: %w", err)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return VaultPasswordChangeResult{}, err
	}
	repo, err = database.GetRepository(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	if candidate == repo.Passphrase {
		return VaultPasswordChangeResult{}, errUnchangedVaultPassword
	}
	if err := database.ValidateRepositoryMutationAdmission(db, repo.ID); err != nil {
		return VaultPasswordChangeResult{}, err
	}
	repo, err = repositoryadmission.AdmitUnderLock(ctx, db, repo)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	store := (vaultprofile.Store{Repository: repo})
	if err := store.AssertRootOwner(ctx, repo.ClientUUID, repo.ProfileUUID, repo.AttachmentGeneration); err != nil {
		return VaultPasswordChangeResult{}, err
	}
	operationUUID := uuid.NewString()
	operation, err := database.BeginVaultPasswordChange(db, repo.ID, operationUUID, candidate)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	repo.PendingPassphrase = candidate
	if _, err := vaultprofile.PreparePasswordRotationStage(repo.ID, operationUUID); err != nil {
		_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
		return passwordChangeResult(repo, operation), err
	}
	return resumeVaultPasswordChangeUnderLock(ctx, db, repo, operation)
}

// RecoverVaultPasswordChange is the Retry of an unfinished password change.
// It waits up to vaultPasswordRetryFenceWait for a native password command
// that an earlier Replicaro process left running.
func RecoverVaultPasswordChange(ctx context.Context, db *sql.DB, repositoryID string, lock VaultLock) (VaultPasswordChangeResult, error) {
	return recoverVaultPasswordChangeWaitingForFence(ctx, db, repositoryID, lock, vaultPasswordRetryFenceWait)
}

// recoverVaultPasswordChangeWaitingForFence recovers the change in this
// order: the vault lock; for a change whose native command may have started
// (native_started with a stage record), the native-process fence, waiting up
// to fenceWait (0 waits as long as ctx allows); the checks of the vault's
// storage, identity and protected metadata, with the password probes inside
// them; and only then the recovery itself. The fence comes before the checks
// so a filesystem vault's bounded check time is never spent waiting for it.
func recoverVaultPasswordChangeWaitingForFence(ctx context.Context, db *sql.DB, repositoryID string, lock VaultLock, fenceWait time.Duration) (VaultPasswordChangeResult, error) {
	if _, err := database.GetRepository(db, repositoryID); err != nil {
		return VaultPasswordChangeResult{}, err
	}
	if _, err := database.VaultPasswordChange(db, repositoryID); err != nil {
		return VaultPasswordChangeResult{}, err
	}
	unlock, err := lock(ctx, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	defer unlock()
	// Read both again under the lock: a waiting retry resumes whatever the
	// phase record says now, not what it said when the request was queued.
	repo, err := database.GetRepository(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	operation, err := database.VaultPasswordChange(db, repositoryID)
	if err != nil {
		return VaultPasswordChangeResult{}, err
	}
	var native *recordedNativeRecovery
	if operation.Phase == "native_started" {
		record, recordErr := loadVaultPasswordRecord(repo.ID, operation.OperationUUID)
		switch {
		case errors.Is(recordErr, vaultprofile.ErrPasswordRotationRecordMissing):
			// Saved by a build without stage records: the older handling below.
		case recordErr != nil:
			return passwordChangeResult(repo, operation), fmt.Errorf("read the password change's recovery record: %w", recordErr)
		default:
			fence, fenceErr := acquireVaultPasswordFence(ctx, repo.ID, operation.OperationUUID, fenceWait)
			if fenceErr != nil {
				recordNativeStartedStopReason(ctx, db, repo.ID, operation, fenceErr)
				return passwordChangeResult(repo, operation), fenceErr
			}
			defer fence.Close()
			native = &recordedNativeRecovery{record: record, fence: fence}
		}
	}
	if operation.Phase != "cleanup_pending" {
		repo, err = admitVaultPasswordRecoveryUnderLock(ctx, db, repo, operation, native)
		if err != nil {
			recordNativeStartedStopReason(ctx, db, repositoryID, operation, err)
			result := passwordChangeResult(repo, operation)
			if native != nil && native.restoredBlobcfg {
				result.Message += " " + kopiaBlobcfgRestoredNote
			}
			return result, err
		}
	}
	return resumeVaultPasswordChange(ctx, db, repo, operation, native)
}

func admitVaultPasswordRecoveryUnderLock(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (models.Repository, error) {
	assertControlPlane := func(ctx context.Context, frozen models.Repository) error {
		oldStore := (vaultprofile.Store{Repository: frozen})
		switch operation.Phase {
		case "preparing":
			return assertVaultPasswordChangeAuthority(ctx, oldStore, frozen, operation, true, false)
		case "native_started":
			// A rollback in progress may already have removed some fences, so
			// it is accepted with any of them gone, in the order rollback
			// removes them. A change with a stage record saves its rollback
			// flag before the first fence goes, so only that flag says so; the
			// recorded native result says it only for a change saved without
			// a record.
			if (native == nil && conclusivePreMutationRollback(repo.Engine, operation)) || (native != nil && native.record.RollingBack) {
				return assertVaultPasswordChangeAuthority(ctx, oldStore, frozen, operation, true, false)
			}
			return assertVaultPasswordChangeAuthority(ctx, oldStore, frozen, operation, false, true)
		case "publishing":
			if err := oldStore.AssertPasswordChangeRootState(ctx, frozen.ProfileUUID, operation.OperationUUID, true); err == nil {
				return nil
			}
			candidate := frozen
			candidate.Passphrase = frozen.PendingPassphrase
			newStore := (vaultprofile.Store{Repository: candidate})
			return newStore.AssertPasswordChangeRootState(ctx, frozen.ProfileUUID, operation.OperationUUID, false)
		default:
			return fmt.Errorf("vault-password recovery phase is invalid")
		}
	}
	selectPassword := func(ctx context.Context, frozen models.Repository) (string, error) {
		switch operation.Phase {
		case "preparing":
			return frozen.Passphrase, nil
		case "native_started":
			if native != nil {
				probe, err := probeNativePasswordChange(ctx, frozen, native)
				if err != nil {
					return "", err
				}
				native.probe = &probe
				switch {
				case native.record.RollingBack:
					return frozen.Passphrase, nil
				case probe.candidateOpens:
					return frozen.PendingPassphrase, nil
				case probe.committedOpens:
					return frozen.Passphrase, nil
				}
				return "", errNeitherVaultPasswordOpens
			}
			if err := probeVaultPassword(ctx, frozen, frozen.PendingPassphrase); err == nil {
				return frozen.PendingPassphrase, nil
			}
			if err := probeVaultPassword(ctx, frozen, frozen.Passphrase); err == nil {
				return frozen.Passphrase, nil
			}
			return "", fmt.Errorf("neither saved vault-password candidate verifies the exact native repository")
		case "publishing":
			return frozen.PendingPassphrase, nil
		default:
			return "", fmt.Errorf("vault-password recovery phase is invalid")
		}
	}
	return admitPasswordChangeRecoveryUnderLock(ctx, db, repo,
		repositoryadmission.PasswordChangeRecoveryOptions{
			OperationUUID: operation.OperationUUID, Phase: operation.Phase,
			AssertControlPlane: assertControlPlane, SelectPassword: selectPassword,
		})
}

func preparePasswordChange(ctx context.Context, repo models.Repository, operation database.VaultPasswordChangeOperation) (vaultprofile.PasswordRotationInventory, error) {
	store := (vaultprofile.Store{Repository: repo})
	assertAuthority := func(allowUnfenced, requireProfileFence bool) error {
		return assertVaultPasswordChangeAuthority(ctx, store, repo, operation, allowUnfenced, requireProfileFence)
	}
	restartable := func(prior error) bool {
		if prior == nil || errors.Is(prior, vaultprofile.ErrPasswordChangeAuthority) {
			return false
		}
		_, freshErr := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, false)
		return freshErr == nil
	}
	// Restarts after a failure wait first and are limited, including a capture
	// that fails after the quiet period: a fence write that keeps failing while
	// reads still work (a full disk, read-only credentials) would otherwise
	// retry at full speed for as long as the change holds the vault lock, and a
	// change that holds the lock can't be cancelled. At the limit the last error
	// is returned, so the caller rolls the preparation back as for any other
	// failure.
	restarts := 0
	restartAfter := func(prior error) error {
		if restarts >= vaultPasswordPrepareRestartLimit {
			return fmt.Errorf("vault-password change preparation still failed after %d restarts: %w", restarts, prior)
		}
		delay := vaultPasswordPrepareRestartBackoff << restarts
		restarts++
		return waitVaultPasswordPrepareRestart(ctx, delay)
	}
	for {
		if err := assertAuthority(true, false); err != nil {
			return vaultprofile.PasswordRotationInventory{}, err
		}
		observed, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, false)
		if err != nil {
			return observed, err
		}
		if err := store.SetPasswordChangeFence(ctx, observed, true); err != nil {
			if restartable(err) {
				if waitErr := restartAfter(err); waitErr != nil {
					return observed, waitErr
				}
				continue
			}
			return observed, err
		}
		if err := assertAuthority(false, true); err != nil {
			return observed, err
		}
		fenced, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, true)
		if err != nil {
			if restartable(err) {
				if waitErr := restartAfter(err); waitErr != nil {
					return fenced, waitErr
				}
				continue
			}
			return fenced, err
		}
		if err := store.DeletePasswordChangePending(ctx, fenced); err != nil {
			return fenced, err
		}
		stable, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, true)
		if err != nil {
			return stable, err
		}
		if len(stable.Pending) != 0 {
			if waitErr := restartAfter(errPasswordChangePendingReappeared); waitErr != nil {
				return stable, waitErr
			}
			continue
		}
		timer := time.NewTimer(vaultPasswordQuietPeriod)
		select {
		case <-ctx.Done():
			timer.Stop()
			return stable, ctx.Err()
		case <-timer.C:
		}
		rechecked, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, true)
		if err != nil {
			if restartable(err) {
				if waitErr := restartAfter(err); waitErr != nil {
					return rechecked, waitErr
				}
				continue
			}
			return rechecked, err
		}
		if !vaultprofile.PasswordRotationInventoriesEqual(stable, rechecked) {
			continue
		}
		if err := vaultprofile.ResetPasswordRotationStage(repo.ID, operation.OperationUUID); err != nil {
			return rechecked, err
		}
		if err := vaultprofile.StagePasswordRotationInventory(repo.ID, operation.OperationUUID, rechecked); err != nil {
			return rechecked, err
		}
		staged, err := loadVaultPasswordStage(repo.ID, operation.OperationUUID)
		if err != nil {
			return rechecked, err
		}
		final, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, true)
		if err != nil {
			if restartable(err) {
				if waitErr := restartAfter(err); waitErr != nil {
					return final, waitErr
				}
				continue
			}
			return final, err
		}
		if !vaultprofile.PasswordRotationInventoriesEqual(staged, final) {
			continue
		}
		if err := assertAuthority(false, true); err != nil {
			return final, err
		}
		return staged, nil
	}
}

func rollbackPreparingPasswordChange(db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	store := (vaultprofile.Store{Repository: repo})
	if err := assertVaultPasswordChangeAuthority(ctx, store, repo, operation, true, false); err != nil {
		return err
	}
	inventory, err := store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, false)
	if err == nil {
		err = store.DeletePasswordChangeOperationPending(ctx, inventory)
	}
	if err == nil {
		inventory, err = store.CapturePasswordRotationInventory(ctx, operation.OperationUUID, false)
	}
	if err == nil {
		err = assertVaultPasswordChangeAuthority(ctx, store, repo, operation, true, false)
	}
	if err == nil {
		err = store.SetPasswordChangeFence(ctx, inventory, false)
	}
	if err != nil {
		return err
	}
	if cleanupErr := vaultprofile.CleanupPasswordRotationStage(repo.ID, operation.OperationUUID); cleanupErr != nil {
		return cleanupErr
	}
	return database.AbandonPreparedVaultPasswordChange(db, repo.ID)
}

type nativePasswordRecoveryDecision int

const (
	nativePasswordRecoveryAmbiguous nativePasswordRecoveryDecision = iota
	nativePasswordRecoveryForward
	nativePasswordRecoveryAbandon
)

func decideNativePasswordRecovery(engine, nativeStatus, disposition string, candidateWorks, committedWorks bool) nativePasswordRecoveryDecision {
	if candidateWorks {
		return nativePasswordRecoveryForward
	}
	if committedWorks && (nativeStatus == "not_started" ||
		(engine == engines.ResticID && nativeStatus == "failed" &&
			disposition == string(engines.PasswordMutationRejectedBeforeMutation))) {
		return nativePasswordRecoveryAbandon
	}
	return nativePasswordRecoveryAmbiguous
}

func conclusivePreMutationRollback(engine string, operation database.VaultPasswordChangeOperation) bool {
	if operation.NativeStatus == "not_started" {
		return operation.NativeMutationDisposition == string(engines.PasswordMutationUnknown)
	}
	return engine == engines.ResticID && operation.NativeStatus == "failed" &&
		operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation)
}

// validatePreMutationRollbackInventory accepts the exact partial states that
// profile-first/root-last cleanup can leave behind. Capture already bounds the
// protected inventory; this check keeps a foreign fence or root-first residue
// from becoming valid cleanup input.
func validatePreMutationRollbackInventory(repo models.Repository, operation database.VaultPasswordChangeOperation, inventory vaultprofile.PasswordRotationInventory) (bool, error) {
	rootFound, rootFenced, profileFenced := false, false, false
	for _, object := range inventory.Objects {
		switch object.Role {
		case "root_canonical":
			rootFound = true
			root, err := vaultprofile.ParseRoot(object.Data, repo.Connector)
			if err != nil {
				return false, fmt.Errorf("validate password-change rollback root: %w", err)
			}
			if root.PasswordChange != nil {
				if root.PasswordChange.OperationUUID != operation.OperationUUID {
					return false, fmt.Errorf("protected vault root has a foreign password-change fence")
				}
				rootFenced = true
			}
		case "profile_canonical":
			profile, err := vaultprofile.Parse(object.Data)
			if err != nil {
				return false, fmt.Errorf("validate password-change rollback profile: %w", err)
			}
			if profile.PasswordChange != nil {
				if profile.PasswordChange.OperationUUID != operation.OperationUUID {
					return false, fmt.Errorf("protected profile has a foreign password-change fence")
				}
				profileFenced = true
			}
		}
	}
	if !rootFound {
		return false, fmt.Errorf("canonical protected vault root is required")
	}
	if !rootFenced && profileFenced {
		return false, fmt.Errorf("password-change rollback fence order is invalid")
	}
	return rootFenced || profileFenced, nil
}

func rollbackConclusivePreMutationPasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation) error {
	if !conclusivePreMutationRollback(repo.Engine, operation) {
		return fmt.Errorf("native password change lacks conclusive pre-mutation evidence")
	}
	if err := rollbackPasswordChangeRemoteFences(ctx, repo, operation); err != nil {
		return err
	}
	if err := cleanupVaultPasswordStage(repo.ID, operation.OperationUUID); err != nil {
		return err
	}
	return abandonConclusivePreMutationPasswordChange(db, repo, operation)
}

// rollbackPasswordChangeRemoteFences removes this operation's pending
// objects and then its fences, profiles first and the root last, accepting
// any state an interrupted earlier run of it leaves behind. It ends with the
// owner checked again, so the local cleanup that follows acts for an
// unchanged owner.
func rollbackPasswordChangeRemoteFences(ctx context.Context, repo models.Repository, operation database.VaultPasswordChangeOperation) error {
	store := (vaultprofile.Store{Repository: repo})
	if err := assertVaultPasswordChangeAuthority(ctx, store, repo, operation, true, false); err != nil {
		return err
	}
	inventory, err := captureVaultPasswordRollbackInventory(ctx, store, operation.OperationUUID)
	if err != nil {
		return err
	}
	if _, err := validatePreMutationRollbackInventory(repo, operation, inventory); err != nil {
		return err
	}
	if err := deleteVaultPasswordRollbackPending(ctx, store, inventory); err != nil {
		return err
	}
	inventory, err = captureVaultPasswordRollbackInventory(ctx, store, operation.OperationUUID)
	if err != nil {
		return err
	}
	hasFence, err := validatePreMutationRollbackInventory(repo, operation, inventory)
	if err != nil {
		return err
	}
	if err := assertVaultPasswordChangeAuthority(ctx, store, repo, operation, true, false); err != nil {
		return err
	}
	if hasFence {
		if err := removeVaultPasswordChangeFence(ctx, repo, inventory); err != nil {
			return err
		}
	}
	final, err := captureVaultPasswordRollbackInventory(ctx, store, operation.OperationUUID)
	if err != nil {
		return err
	}
	finalFenced, err := validatePreMutationRollbackInventory(repo, operation, final)
	if err != nil {
		return err
	}
	if finalFenced || len(final.Pending) != 0 {
		return fmt.Errorf("password-change rollback remote cleanup is incomplete")
	}
	return assertVaultPasswordChangeAuthority(ctx, store, repo, operation, true, false)
}

func recoverNativeTruth(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation) (bool, error) {
	candidateWorks := probeVaultPassword(ctx, repo, repo.PendingPassphrase) == nil
	committedWorks := false
	if !candidateWorks {
		committedWorks = probeVaultPassword(ctx, repo, repo.Passphrase) == nil
	}
	switch decideNativePasswordRecovery(repo.Engine, operation.NativeStatus, operation.NativeMutationDisposition, candidateWorks, committedWorks) {
	case nativePasswordRecoveryForward:
		return true, nil
	case nativePasswordRecoveryAbandon:
		return false, rollbackConclusivePreMutationPasswordChange(ctx, db, repo, operation)
	default:
		return false, fmt.Errorf("native vault-password outcome is ambiguous; manual recovery is required")
	}
}

func resumeVaultPasswordChangeUnderLock(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation) (VaultPasswordChangeResult, error) {
	return resumeVaultPasswordChange(ctx, db, repo, operation, nil)
}

// resumeVaultPasswordChange continues the change from its saved phase. native
// is the stage record and fence of a native_started change, taken by
// RecoverVaultPasswordChange before its checks; it is nil for a change saved
// in native_started without a record, which keeps the older handling.
func resumeVaultPasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (result VaultPasswordChangeResult, err error) {
	if repo.PendingPassphrase == "" && operation.Phase != "cleanup_pending" {
		return passwordChangeResult(repo, operation), fmt.Errorf("pending vault-password candidate is unavailable; manual recovery is required")
	}
	// A note from forward recovery (the old Restic key could not be removed)
	// and the note that Kopia's kopia.blobcfg was put back stay on whatever
	// this attempt ends with.
	note := ""
	defer func() {
		if native != nil && native.restoredBlobcfg {
			result.Message = strings.TrimSpace(result.Message + " " + kopiaBlobcfgRestoredNote)
		}
		if note != "" {
			result.Message = strings.TrimSpace(result.Message + " " + note)
		}
	}()
	if operation.Phase == "preparing" {
		_, err := prepareVaultPasswordChange(ctx, repo, operation)
		resticKeyID := ""
		var kopiaFormat *vaultprofile.PasswordRotationKopiaFormat
		if err == nil && repo.Engine == engines.ResticID {
			// The key the committed password opens now is the one this change
			// replaces. Reading it before the first launch, with the vault
			// fenced, lets every launch and forward recovery name it.
			resticKeyID, _, err = listVaultPasswordResticKeys(ctx, repo)
			if err != nil {
				err = fmt.Errorf("list the vault's Restic keys before changing its password: %w", err)
			}
		}
		if err == nil && repo.Engine == engines.KopiaID {
			// The copy of Kopia's format blobs that lets recovery undo a
			// change cut off between Kopia's two writes.
			kopiaFormat, err = captureVaultPasswordKopiaFormat(ctx, repo)
		}
		if err != nil {
			_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			if errors.Is(err, vaultprofile.ErrPasswordChangeAuthority) {
				return passwordChangeResult(repo, operation), err
			}
			if errors.Is(context.Cause(ctx), errStartupPasswordRecoveryStopped) {
				// The app is quitting while startup recovery prepares. Keep the
				// phase so the next start resumes it, as it would after a crash;
				// rolling back here would undo a change that only the quit
				// interrupted. A change started from the UI keeps its rollback.
				return passwordChangeResult(repo, operation), err
			}
			if rollbackErr := rollbackPreparingPasswordChange(db, repo, operation); rollbackErr != nil {
				return passwordChangeResult(repo, operation), fmt.Errorf("prepare vault-password change: %v; fence cleanup remains pending: %w", err, rollbackErr)
			}
			return VaultPasswordChangeResult{}, err
		}
		store := (vaultprofile.Store{Repository: repo})
		if err := assertVaultPasswordChangeAuthority(ctx, store, repo, operation, false, true); err != nil {
			_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			return passwordChangeResult(repo, operation), err
		}
		if err := vaultPasswordChangeFault("final_inventory_and_authority_verified"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		// The stage record and the fence exist before native_started is saved,
		// so recovery of any native_started change from this build finds both.
		native, err = beginRecordedNativeRecovery(repo, operation.OperationUUID, resticKeyID, kopiaFormat)
		if err != nil {
			_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			return passwordChangeResult(repo, operation), err
		}
		defer native.fence.Close()
		if err := database.AdvanceVaultPasswordChange(db, repo.ID, "preparing", "native_started"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		operation, _ = database.VaultPasswordChange(db, repo.ID)
		if err := vaultPasswordChangeFault("native_start_persisted"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		var launched VaultPasswordChangeResult
		operation, launched, err = launchNativePasswordChange(ctx, db, repo, operation, native)
		if err != nil {
			return launched, err
		}
	}
	if operation.Phase == "native_started" && native != nil {
		var stopped VaultPasswordChangeResult
		var done bool
		operation, note, stopped, done, err = continueRecordedNativePasswordChange(ctx, db, repo, operation, native)
		if done {
			if err != nil {
				recordNativeStartedStopReason(ctx, db, repo.ID, operation, err)
			}
			return stopped, err
		}
	}
	if operation.Phase == "native_started" {
		forward, err := recoverNativeTruth(ctx, db, repo, operation)
		if err != nil {
			if operation.NativeMutationDisposition != string(engines.PasswordMutationRejectedBeforeMutation) {
				_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			}
			return passwordChangeResult(repo, operation), err
		}
		if !forward {
			result := passwordChangeResult(repo, operation)
			result.CleanupPending = false
			if operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation) {
				result.Phase = "failed"
				result.SidecarStatus = "not_changed"
				result.Message = "Restic rejected the password change because the repository was locked before mutation. The protected recovery metadata and committed password were left unchanged, and this operation's fence and staging were removed."
				if operation.LastError != "" {
					return result, errors.New(operation.LastError)
				}
				return result, fmt.Errorf("native Restic password change was rejected before mutation")
			}
			result.Phase = "not_started"
			result.SidecarStatus = "not_changed"
			result.Message = notStartedPasswordChangeMessage(operation.LastError)
			return result, nil
		}
		if err := database.AdvanceVaultPasswordChangeAfterCandidateVerification(db, repo.ID, operation.OperationUUID); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		operation, _ = database.VaultPasswordChange(db, repo.ID)
	}
	if operation.Phase == "publishing" {
		if err := probeVaultPassword(ctx, repo, repo.PendingPassphrase); err != nil {
			return passwordChangeResult(repo, operation), fmt.Errorf("new native credential no longer verifies the exact repository; manual recovery is required")
		}
		staged, err := loadVaultPasswordStage(repo.ID, operation.OperationUUID)
		if err != nil {
			return passwordChangeResult(repo, operation), fmt.Errorf("durable password-change staging is unavailable; manual recovery is required: %w", err)
		}
		candidate := repo
		candidate.Passphrase = repo.PendingPassphrase
		store := (vaultprofile.Store{Repository: candidate})
		if err := publishVaultPasswordTree(ctx, store, staged); err != nil {
			_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			if operation.NativeStatus == "succeeded" {
				return passwordChangeResult(repo, operation), fmt.Errorf("native vault password changed but protected recovery metadata publication is incomplete: %w", err)
			}
			return passwordChangeResult(repo, operation), fmt.Errorf("%s, but protected recovery metadata publication is incomplete: %w", verifiedCandidateNativeSummary(operation), err)
		}
		if err := vaultPasswordChangeFault("sidecar_tree_published"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		if err := database.CommitVaultPasswordChange(db, repo.ID); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		repo.Passphrase, repo.PendingPassphrase = repo.PendingPassphrase, ""
		operation, _ = database.VaultPasswordChange(db, repo.ID)
		if err := vaultPasswordChangeFault("credential_committed"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
	}
	if operation.Phase == "cleanup_pending" {
		if err := cleanupVaultPasswordStage(repo.ID, operation.OperationUUID); err != nil {
			_ = database.RecordVaultPasswordChangeError(db, repo.ID, err.Error())
			if operation.NativeStatus == "succeeded" {
				return passwordChangeResult(repo, operation), fmt.Errorf("vault password changed successfully but local staging cleanup is pending: %w", err)
			}
			return passwordChangeResult(repo, operation), fmt.Errorf("%s and protected recovery metadata was updated, but local staging cleanup is pending: %w", verifiedCandidateNativeSummary(operation), err)
		}
		if err := vaultPasswordChangeFault("local_cleanup_deleted"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		if err := database.CompleteVaultPasswordChangeCleanup(db, repo.ID); err != nil {
			return passwordChangeResult(repo, operation), err
		}
		result := passwordChangeResult(repo, operation)
		result.Phase, result.SidecarStatus, result.CleanupPending = "completed", "succeeded", false
		if operation.NativeStatus == "succeeded" {
			result.Message = "Vault password changed successfully. Other computers must reconnect and enter the current password."
		} else {
			result.Message = fmt.Sprintf("The pending vault password verified and protected recovery metadata was updated. The recorded native result remains %s. Other computers must reconnect and enter the current password.", nativePasswordResultTruth(operation))
		}
		return result, nil
	}
	return passwordChangeResult(repo, operation), fmt.Errorf("vault-password change phase is invalid")
}

// VaultPasswordChangeOutcome is the status of the tracked operation that ran
// a password change or its retry. The phase record decides it:
//
//   - completed: success, or completed_with_issues when the new password
//     verified and was committed although the native command did not report
//     success (the change took effect; the engine's own result stands as
//     recorded);
//   - cleanup_pending: completed_with_issues; the new password is committed and
//     only local staging cleanup is left, which Retry finishes;
//   - anything else is failed: the change stopped before commit (the vault is
//     blocked until it is retried), was rolled back because the native
//     command never started, failed, or was interrupted too often while only
//     the old password opened the vault, or was refused before any change.
func VaultPasswordChangeOutcome(result VaultPasswordChangeResult, err error) string {
	if err == nil && result.Phase == "completed" {
		if result.Native.Status == engines.RequestedOperationSucceeded {
			return "success"
		}
		return "completed_with_issues"
	}
	if result.Phase == "cleanup_pending" {
		return "completed_with_issues"
	}
	return "failed"
}

// VaultPasswordChangeSummary is the final output of the password change
// operation: the error, if any, the result's own explanation, and the native
// command's result line with its output. It never contains a password.
//
// The native line keeps the shape the vault card used when the change still
// answered in its HTTP response ("Native restic result: failed — <output>").
// The output is the engine's own stdout/stderr, which was always shown to the
// user: Restic reads the new password from a file and Kopia from
// KOPIA_NEW_PASSWORD, and neither prints it. It is already bounded by the
// command runner's capture, so it is not cut again here. Keep it in this
// summary: the operation log, the toast and the vault card read only this
// final output now, and without it a D32 completed-with-issues change or a
// Restic rejection before mutation would hide what the engine actually said.
func VaultPasswordChangeSummary(result VaultPasswordChangeResult, err error) string {
	lines := []string{}
	if err != nil {
		lines = append(lines, err.Error())
	}
	if result.Message != "" {
		lines = append(lines, result.Message)
	}
	if result.ResticKeyTruth != "" {
		lines = append(lines, result.ResticKeyTruth)
	}
	output := strings.TrimSpace(result.Native.Output)
	if result.Native.Engine != "" && (result.Native.Status != "" || output != "") {
		status := string(result.Native.Status)
		if status == "" {
			status = "unresolved"
		}
		line := fmt.Sprintf("Native %s result: %s", result.Native.Engine, status)
		if output != "" {
			line += " — " + output
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// VaultPasswordChangeBlockingStep is the operation step a failed password
// change records when it leaves the vault blocked: a change stopped before
// commit refuses every operation on the vault until it is retried. The
// dashboard reads this step to say so and to lead to the retry; it is a fact
// about the moment the operation ended, so a later successful retry does not
// have to rewrite it.
const VaultPasswordChangeBlockingStep = "vault_password_blocked"

// VaultPasswordChangeBlockingText is the step's log text. The UI shows its own
// translated wording for the step.
const VaultPasswordChangeBlockingText = "An unfinished vault password change is blocking this vault. Retry the password change to continue."

// RecordVaultPasswordChangeBlocking records VaultPasswordChangeBlockingStep on
// the operation when the vault's password change phase record is still before
// commit. Errors are only logged: the operation's own status is what matters.
func RecordVaultPasswordChangeBlocking(db *sql.DB, operationID, repositoryID string) {
	if !errors.Is(database.RequireNoPrecommitVaultPasswordChange(db, repositoryID), database.ErrVaultPasswordChangeRecoveryRequired) {
		return
	}
	now := time.Now()
	if err := database.StartOperationStep(db, operationID, "orchestration", VaultPasswordChangeBlockingStep, now); err != nil {
		log.Printf("record blocked vault for password change operation %s: %v", operationID, err)
		return
	}
	if err := database.FinishOperationStep(db, operationID, VaultPasswordChangeBlockingStep, "failed", VaultPasswordChangeBlockingText, now); err != nil {
		log.Printf("record blocked vault for password change operation %s: %v", operationID, err)
	}
}

// errStartupPasswordRecoveryStopped is the cause the startup recovery is
// cancelled with when the app quits, as opposed to running out of its time.
var errStartupPasswordRecoveryStopped = errors.New("application is stopping")

// startupPasswordRecoveryVaults lists the vaults whose startup recovery has not
// ended yet. A request reads it to refuse a second change or Retry for such a
// vault instead of queuing one that would only run after the recovery, on
// whatever the recovery left behind.
var startupPasswordRecoveryVaults = struct {
	sync.Mutex
	ids map[string]bool
}{ids: map[string]bool{}}

// StartupPasswordRecoveryRunning reports whether startup recovery still holds
// the vault for its unfinished password change.
func StartupPasswordRecoveryRunning(repositoryID string) bool {
	startupPasswordRecoveryVaults.Lock()
	defer startupPasswordRecoveryVaults.Unlock()
	return startupPasswordRecoveryVaults.ids[repositoryID]
}

func setStartupPasswordRecoveryRunning(repositoryID string, running bool) {
	startupPasswordRecoveryVaults.Lock()
	defer startupPasswordRecoveryVaults.Unlock()
	if running {
		startupPasswordRecoveryVaults.ids[repositoryID] = true
	} else {
		delete(startupPasswordRecoveryVaults.ids, repositoryID)
	}
}

// StartupPasswordRecovery is the one startup attempt at every unfinished
// vault-password change. It never polls or starts a retry service.
//
// PrepareStartupPasswordRecovery runs before any worker or HTTP request
// exists. It takes the vault lock of every change that still has to reach the
// vault and keeps it; Start, called once the UI is served, lets the attempt
// run in the background. The vault can stall (unreachable storage, a hung
// sidecar command) for the whole 30-minute bound, and that must not keep the
// UI and every other vault waiting. Backups and background workers take the
// vault lock first, so they wait until its attempt ends; request kinds that
// check the phase record (restore, check, maintenance, settings and the like)
// are refused while it exists, and keep being refused afterwards if the
// change is still unfinished. A change left in cleanup_pending only removes local staging
// files, which can't stall on the vault's storage, so Prepare finishes those
// at once and the vault is free from the start.
//
// It also finishes the password change operations that were still running
// when the app stopped. Startup reconciliation leaves those running on
// purpose, because recovery follows the phase record, not the operation
// record: each one is finished with the outcome of the attempt for its vault.
// Until then the vault card shows it as still running.
//
// A failed or completed-with-issues outcome notifies like any other tracked
// operation that ends that way (the user was never told how the change they
// started ended). Before the desktop integration exists a desktop
// notification would be dropped silently while its step still reported
// success, so each notification step is registered before its operation is
// saved as finished, exactly as a worker does, and sent only after
// DeliverNotifications. If the app stops before that, the step is still
// running and the next startup's reconciliation marks it failed with "did not
// complete because the application stopped"; nothing else needs to be saved.
// An interrupted outcome never notifies, as for every other operation.
//
// Quitting stops the attempt. A change whose phase record is still there
// keeps its operation records running, with no outcome and no notification,
// for the next start to finish. A quit while preparing keeps the phase, so
// the next start resumes it. A quit during the native command cancels that
// command and records it as interrupted; the next start then finishes the
// change if the new password already opens the vault, or runs the command
// again (at most three reruns in all, then a rollback), as after a crash.
type StartupPasswordRecovery struct {
	db            *sql.DB
	ctx           context.Context
	stop          context.CancelCauseFunc
	cancelTimeout context.CancelFunc
	published     chan struct{}
	done          chan struct{}

	notifications sync.Mutex
	deliver       bool
	dispatches    []func()
}

type reservedPasswordRecovery struct {
	repositoryID string
	unlock       func()
	operationIDs []string
}

// PrepareStartupPasswordRecovery reserves the vaults and finishes everything
// that needs no vault access. timeout bounds the whole attempt.
func PrepareStartupPasswordRecovery(db *sql.DB, timeout time.Duration) (*StartupPasswordRecovery, error) {
	operations, err := database.ListVaultPasswordChanges(db)
	if err != nil {
		return nil, err
	}
	running, err := database.RunningVaultPasswordChangeOperations(db)
	if err != nil {
		return nil, err
	}
	runningByVault := map[string][]string{}
	for _, operation := range running {
		runningByVault[operation.RepositoryID] = append(runningByVault[operation.RepositoryID], operation.OperationID)
	}
	stoppable, stop := context.WithCancelCause(context.Background())
	ctx, cancelTimeout := context.WithTimeout(stoppable, timeout)
	recovery := &StartupPasswordRecovery{db: db, ctx: ctx, stop: stop, cancelTimeout: cancelTimeout,
		published: make(chan struct{}), done: make(chan struct{})}
	var vaults []reservedPasswordRecovery
	for _, operation := range operations {
		operationIDs := runningByVault[operation.RepositoryID]
		delete(runningByVault, operation.RepositoryID)
		if operation.Phase == "cleanup_pending" {
			result, err := RecoverVaultPasswordChange(ctx, db, operation.RepositoryID, TryVaultLock)
			recovery.finishVault(operation.RepositoryID, operationIDs, result, err)
			continue
		}
		unlock, err := TryVaultLock(ctx, operation.RepositoryID)
		if err != nil {
			recovery.finishVault(operation.RepositoryID, operationIDs, VaultPasswordChangeResult{}, err)
			continue
		}
		setStartupPasswordRecoveryRunning(operation.RepositoryID, true)
		vaults = append(vaults, reservedPasswordRecovery{repositoryID: operation.RepositoryID, unlock: unlock, operationIDs: operationIDs})
	}
	// A running record whose vault has no phase record: the app stopped before
	// the change saved its phase (nothing was changed), or after the change
	// finished but before its record was saved. Those cannot be told apart
	// now, so the record is interrupted like any other abandoned operation.
	for _, operationIDs := range runningByVault {
		for _, operationID := range operationIDs {
			recovery.finishOperation(operationID, "interrupted",
				"Application stopped before the operation completed; the operation was marked interrupted.")
		}
	}
	go recovery.run(vaults)
	return recovery, nil
}

func (recovery *StartupPasswordRecovery) run(vaults []reservedPasswordRecovery) {
	defer close(recovery.done)
	defer recovery.cancelTimeout()
	select {
	case <-recovery.ctx.Done():
		for _, vault := range vaults {
			recovery.release(vault)
		}
		return
	case <-recovery.published:
	}
	// Each vault recovers on its own, under the shared bound, the same way
	// changes started from the UI run side by side. One after another, a vault
	// whose storage stalls would keep every later vault reserved, and the
	// workers waiting for those vaults blocked, for up to the whole bound, and
	// could leave the later vaults no time for their attempt at all.
	var recovering sync.WaitGroup
	for _, vault := range vaults {
		recovering.Add(1)
		go func() {
			defer recovering.Done()
			defer recovery.release(vault)
			recovery.recoverVault(vault)
		}()
	}
	recovering.Wait()
}

func (recovery *StartupPasswordRecovery) recoverVault(vault reservedPasswordRecovery) {
	if recovery.stopping() {
		return
	}
	// The lock is already held; RecoverVaultPasswordChange only takes it over,
	// and it is released once the outcome is saved.
	held := func(context.Context, string) (func(), error) { return func() {}, nil }
	// A native command an earlier Replicaro process left running is waited
	// for as long as the startup bound allows.
	result, err := recoverVaultPasswordChangeWaitingForFence(recovery.ctx, recovery.db, vault.repositoryID, held, 0)
	if !recovery.stopping() || !recovery.phaseRecordRemains(vault.repositoryID) {
		recovery.finishVault(vault.repositoryID, vault.operationIDs, result, err)
	}
}

func (recovery *StartupPasswordRecovery) release(vault reservedPasswordRecovery) {
	setStartupPasswordRecoveryRunning(vault.repositoryID, false)
	vault.unlock()
}

func (recovery *StartupPasswordRecovery) stopping() bool {
	return errors.Is(context.Cause(recovery.ctx), errStartupPasswordRecoveryStopped)
}

// phaseRecordRemains reports whether the vault still has its phase record. A
// read error counts as yes: leaving the operation running only means the next
// start finishes it.
func (recovery *StartupPasswordRecovery) phaseRecordRemains(repositoryID string) bool {
	_, err := database.VaultPasswordChange(recovery.db, repositoryID)
	return !errors.Is(err, sql.ErrNoRows)
}

func (recovery *StartupPasswordRecovery) finishVault(repositoryID string, operationIDs []string, result VaultPasswordChangeResult, err error) {
	if err != nil {
		log.Printf("vault-password recovery %s remains blocked: %v", repositoryID, err)
	}
	status := VaultPasswordChangeOutcome(result, err)
	if err == nil && result.Phase == "not_started" {
		// Recovery proved the interrupted change never touched the vault and
		// rolled its fence back. The restart is what stopped it.
		status = "interrupted"
	}
	for _, operationID := range operationIDs {
		if status == "failed" {
			RecordVaultPasswordChangeBlocking(recovery.db, operationID, repositoryID)
		}
		recovery.finishOperation(operationID, status, VaultPasswordChangeSummary(result, err))
	}
}

func (recovery *StartupPasswordRecovery) finishOperation(operationID, status, output string) {
	var dispatch func()
	if status != "interrupted" {
		dispatch = prepareStartupPasswordNotification(recovery.db, operationID, status)
	}
	if err := database.FinishOperation(recovery.db, operationID, status, output, time.Now()); err != nil {
		log.Printf("finish vault-password operation %s after startup recovery: %v", operationID, err)
		return
	}
	if dispatch == nil {
		return
	}
	recovery.notifications.Lock()
	if !recovery.deliver {
		recovery.dispatches = append(recovery.dispatches, dispatch)
		recovery.notifications.Unlock()
		return
	}
	recovery.notifications.Unlock()
	dispatch()
}

// Start lets the reserved vaults' recovery run. Call it once, after the UI is
// served.
func (recovery *StartupPasswordRecovery) Start() { close(recovery.published) }

// DeliverNotifications sends the notifications of outcomes saved so far, and
// of every later one as it is saved. Call it once desktop notifications can
// be shown.
func (recovery *StartupPasswordRecovery) DeliverNotifications() {
	recovery.notifications.Lock()
	recovery.deliver = true
	pending := recovery.dispatches
	recovery.dispatches = nil
	recovery.notifications.Unlock()
	for _, dispatch := range pending {
		dispatch()
	}
}

// Cancel stops the attempt without waiting for it. Shutdown calls it before
// the HTTP drain, because a request may be waiting for a vault lock the
// recovery holds.
func (recovery *StartupPasswordRecovery) Cancel() { recovery.stop(errStartupPasswordRecoveryStopped) }

// Done is closed when the attempt has ended and every reserved vault lock is
// released.
func (recovery *StartupPasswordRecovery) Done() <-chan struct{} { return recovery.done }

// Stop cancels the attempt and waits for it to end, so the database can be
// closed afterwards.
func (recovery *StartupPasswordRecovery) Stop(ctx context.Context) error {
	recovery.Cancel()
	select {
	case <-recovery.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// prepareStartupPasswordNotification is the startup counterpart of the API's
// prepareOperationNotification for a password change operation, which the
// runner cannot import. It registers the notification step and returns the
// send, or nil when nothing is to be sent. The title prefix is the one the API
// gives these operations ("Change vault password: <vault>").
func prepareStartupPasswordNotification(db *sql.DB, operationID, status string) func() {
	operation, err := database.GetOperation(db, operationID)
	if err != nil {
		log.Printf("prepare notification for vault-password operation %s: %v", operationID, err)
		return nil
	}
	return notifications.PrepareOperation(db, operationID, status, database.GetSettings, func(settings models.Settings) notifications.Event {
		event := notifications.Event{
			Event: database.VaultPasswordChangeKind, Status: status, Success: status == "success",
			Title: operation.Title, OperationID: operationID,
			Locale: locale.Effective(settings.Language),
		}
		if name, ok := strings.CutPrefix(operation.Title, "Change vault password: "); ok {
			event.TaskKey, event.TaskName = "notifications.task.changeVaultPassword", name
		}
		return event
	})
}
