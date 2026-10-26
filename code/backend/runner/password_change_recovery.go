package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/database"
	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/models"
	"github.com/local/replicaro/vaultprofile"
)

// Recovery of an interrupted native password command.
//
// A password change runs one native command: Restic `key passwd` (add a key
// for the new password, then remove the old key) or Kopia `repository
// change-password` (rewrite kopia.blobcfg, then kopia.repository). Killed
// partway, the pinned engines leave one of these states:
//
//   - Restic: only the old password opens, after about half a second also
//     with the command's exclusive lock left behind; both passwords open (the
//     new key is written and the old one not yet removed), always with the
//     lock; or only the new password opens, now and then with the lock.
//   - Kopia: only the old password opens (nothing written yet); neither opens
//     (kopia.blobcfg already rewritten, kopia.repository not yet); or only the
//     new password opens. Kopia was never seen writing kopia.repository first.
//
// The Kopia state that neither password opens has no native way back, so the
// change saves both format blobs before the first launch and recovery puts
// the saved kopia.blobcfg back when it finds that state (see
// restoreSplitKopiaBlobcfg). The old password then opens the vault again and
// the change continues as if the command had been cut off before writing.
//
// Recovery first makes sure the earlier command has really stopped: the
// command and everything recovery itself runs against the repository (the
// reruns, Restic unlock and key removal) inherit the change's native-process
// fence, and recovery takes that fence before it looks at the vault. Within
// one process, the finished wait on the child shows the same thing. It never
// stops a command that still holds the fence; it waits for a bounded time and
// otherwise leaves the change to be retried.
//
// Then it checks which password opens the vault, candidate first, and acts on
// that together with the recorded native result:
//
//   - the new password opens: finish the change (for Restic, also remove the
//     recorded old key if the interrupted command left it behind);
//   - only the old password opens and the command was interrupted or never
//     reported: run it again, at most three times in all, then roll back;
//   - only the old password opens and the command failed or never started:
//     roll back and report the engine's error;
//   - only the old password opens although the command reported success:
//     leave the change to be retried; never roll back a reported success;
//   - neither opens: leave the change to be retried, unless it is the Kopia
//     state above, which is undone first and then handled as "only the old
//     password opens".
//
// A change saved in native_started by a build that wrote no stage record keeps
// the older handling (forward when the new password opens, a rollback only
// for a command that never started or that Restic rejected before changing
// anything, manual recovery otherwise), because nothing tells recovery how
// far it got.

// vaultPasswordMaximumReruns is how many times recovery starts an interrupted
// native password command again before it rolls the change back. Each rerun
// that is cut off again usually means something keeps ending Replicaro
// mid-change; rolling back then gives the user a vault with its old password
// and a clear message instead of an endless loop.
const vaultPasswordMaximumReruns = 3

// vaultPasswordRetryFenceWait bounds how long a Retry waits for an earlier
// native password command that still runs (for example one a crashed
// Replicaro left behind on Linux, where the password commands don't end with
// Replicaro). Five minutes is far longer than either command takes, and
// short enough that a Retry doesn't look stuck. Startup recovery waits up to
// its own 30-minute bound instead.
var vaultPasswordRetryFenceWait = 5 * time.Minute

// vaultPasswordFenceWaitInterval is how often a waiting recovery looks at the
// fence again.
var vaultPasswordFenceWaitInterval = 2 * time.Second

var vaultPasswordFenceInactive = command.NativeProcessFenceInactive

var (
	errEarlierPasswordCommandRunning        = errors.New("an earlier vault password command for this vault is still running; Replicaro waits for it to finish and never stops it. Restarting the computer ends it. Retry the password change afterwards")
	errResticLiveLock                       = errors.New("another process holds a lock on this Restic vault right now, so the password change can't continue yet. Retry the password change once that process has finished")
	errNeitherVaultPasswordOpens            = errors.New("neither the new nor the current vault password opens this vault right now, so the password change was left as it is. Retry the password change later")
	errReportedSuccessNotVisible            = errors.New("the engine reported the password change as successful, but only the current vault password opens this vault right now. Retry the password change to check again")
	errPasswordCommandInterrupted           = errors.New("the vault password command was interrupted before it finished. Retry the password change to run it again")
	errPasswordCommandInterruptedRepeatedly = errors.New("the vault password command was interrupted again after it had already been run again 3 times, so the password change was rolled back. Make sure Replicaro can keep running until the change finishes, then change the password again")
	errPasswordChangeRerunMetadata          = errors.New("the protected recovery metadata changed since the password change staged it, so the password command was not run again")
	errKopiaBlobcfgRestoreFailed            = errors.New("an interrupted vault password change had rewritten this Kopia vault's kopia.blobcfg but not its kopia.repository, and Replicaro could not put back and confirm the saved kopia.blobcfg; manual recovery is required")
	errKopiaFormatChanged                   = errors.New("the vault password was not changed: the Kopia repository at the vault's location is not the one this vault was saved with")
)

// resticOldKeyRemainsNote is added to the result when forward recovery could
// not remove the old Restic key. Nothing in the app removes it later.
const resticOldKeyRemainsNote = "The previous vault password still opens this vault, because Replicaro could not remove its Restic key."

var writeVaultPasswordRecord = vaultprofile.WritePasswordRotationRecord
var loadVaultPasswordRecord = vaultprofile.LoadPasswordRotationRecord
var cleanupVaultPasswordStageKeepingRecord = vaultprofile.CleanupPasswordRotationStageKeepingRecord
var abandonRolledBackVaultPasswordChange = database.AbandonRolledBackVaultPasswordChange
var captureVaultPasswordRerunInventory = func(ctx context.Context, store vaultprofile.Store, operationUUID string) (vaultprofile.PasswordRotationInventory, error) {
	return store.CapturePasswordRotationInventory(ctx, operationUUID, true)
}
var listVaultPasswordResticKeys = func(ctx context.Context, repo models.Repository) (string, []string, error) {
	engine, err := resolveVaultPasswordEngine(repo)
	if err != nil {
		return "", nil, err
	}
	return engines.ListResticKeys(ctx, engine, repo)
}
var removeVaultPasswordResticKey = func(ctx context.Context, repo models.Repository, keyID string) error {
	engine, err := resolveVaultPasswordEngine(repo)
	if err != nil {
		return err
	}
	_, err = engines.RemoveResticKey(ctx, engine, repo, keyID)
	return err
}
var showVaultPasswordKopiaFormatBlob = func(ctx context.Context, repo models.Repository, blobID string) ([]byte, error) {
	engine, err := resolveVaultPasswordEngine(repo)
	if err != nil {
		return nil, err
	}
	return engines.ShowKopiaFormatBlob(ctx, engine, repo, blobID)
}
var readVaultPasswordKopiaFormatBlob = vaultprofile.ReadKopiaFormatBlob
var restoreVaultPasswordKopiaBlobcfg = vaultprofile.RestoreKopiaBlobcfg
var forgetVaultPasswordKopiaCachedFormat = engines.ForgetKopiaCachedFormat
var unlockVaultPasswordRestic = func(ctx context.Context, repo models.Repository) error {
	engine, err := resolveVaultPasswordEngine(repo)
	if err != nil {
		return err
	}
	_, err = engines.UnlockResticRepository(ctx, engine, repo)
	return err
}

// kopiaBlobcfgRestoredNote is added to the result of an attempt that put the
// saved kopia.blobcfg back, so the operation's log says that Replicaro wrote
// to the repository and why.
const kopiaBlobcfgRestoredNote = "The interrupted password change had already rewritten this Kopia vault's kopia.blobcfg but not its kopia.repository, so Replicaro put back the kopia.blobcfg saved before the change."

// recordedNativeRecovery is what one attempt knows about a change that has a
// stage record: the record as last saved, the fence this attempt holds, the
// probe result once taken, whether this attempt already launched the native
// command, and whether it put Kopia's saved kopia.blobcfg back.
type recordedNativeRecovery struct {
	record          vaultprofile.PasswordRotationRecord
	fence           *command.NativeProcessFence
	probe           *nativePasswordProbe
	launched        bool
	restoredBlobcfg bool
}

type nativePasswordProbe struct {
	candidateOpens, committedOpens bool
}

type recordedNativeAction int

const (
	recordedNativeResumable recordedNativeAction = iota
	recordedNativeForward
	recordedNativeRerun
	recordedNativeRollback
)

// decideRecordedNativePassword is the table in the comment at the top of this
// file. It is only called once the native command is known to have stopped.
func decideRecordedNativePassword(nativeStatus string, reruns int, probe nativePasswordProbe) recordedNativeAction {
	if probe.candidateOpens {
		return recordedNativeForward
	}
	if !probe.committedOpens {
		return recordedNativeResumable
	}
	switch nativeStatus {
	case "", "interrupted":
		if reruns < vaultPasswordMaximumReruns {
			return recordedNativeRerun
		}
		return recordedNativeRollback
	case "failed", "not_started":
		return recordedNativeRollback
	default:
		// A reported success that only the old password shows (a second Restic
		// key with the old password while the candidate probe failed for a
		// moment) is never rolled back.
		return recordedNativeResumable
	}
}

// beginRecordedNativeRecovery runs just before the first launch: it saves the
// stage record and takes the fence. The caller still has to save
// native_started; from that moment on the record and the fence exist.
func beginRecordedNativeRecovery(repo models.Repository, operationUUID, resticKeyID string, kopiaFormat *vaultprofile.PasswordRotationKopiaFormat) (*recordedNativeRecovery, error) {
	record := vaultprofile.PasswordRotationRecord{
		Version: vaultprofile.PasswordRotationRecordVersion, RepositoryID: repo.ID, OperationUUID: operationUUID,
		Engine: repo.Engine, ResticKeyID: resticKeyID, Kopia: kopiaFormat,
	}
	if err := writeVaultPasswordRecord(record); err != nil {
		return nil, fmt.Errorf("save the password change's recovery record: %w", err)
	}
	path, err := vaultprofile.PasswordRotationFencePath(repo.ID, operationUUID)
	if err != nil {
		return nil, err
	}
	fence, err := acquireSupportedNativeProcessFence(path)
	if err != nil {
		return nil, fmt.Errorf("take the password change's native-process fence: %w", err)
	}
	return &recordedNativeRecovery{record: record, fence: fence}, nil
}

// captureKopiaFormatBeforeLaunch reads Kopia's two format blobs just before
// the first launch, both with `kopia blob show` and straight from the vault's
// storage (the path recovery uses when no password opens the vault), and
// keeps them only when the two reads agree byte for byte. The comparison also
// finds each blob's object name among the spellings Kopia's backends use, so
// recovery never relies on a naming rule per connector.
//
// It refuses the change, before anything native ran, when a blob is missing
// (a repository made by an older Kopia may have no kopia.blobcfg; a missing
// kopia.repository more likely means the storage path doesn't reach Kopia's
// folder), when the reads disagree or match under more than one name, or when
// kopia.repository belongs to another repository. Without a copy it can rely on, an
// interrupted change could leave a vault that neither password opens.
func captureKopiaFormatBeforeLaunch(ctx context.Context, repo models.Repository) (*vaultprofile.PasswordRotationKopiaFormat, error) {
	saved := &vaultprofile.PasswordRotationKopiaFormat{}
	for _, blobID := range []string{engines.KopiaRepositoryBlob, engines.KopiaBlobcfgBlob} {
		stored := map[string][]byte{}
		for _, name := range vaultprofile.KopiaFormatBlobNames(blobID) {
			data, found, err := readVaultPasswordKopiaFormatBlob(ctx, repo, name)
			if err != nil {
				return nil, fmt.Errorf("read Kopia's %s from the vault's storage before changing the vault password: %w", blobID, err)
			}
			if found {
				stored[name] = data
			}
		}
		if len(stored) == 0 && blobID == engines.KopiaRepositoryBlob {
			return nil, fmt.Errorf("the vault password was not changed: Replicaro found no %s file where it reads the vault's storage, so it can't save the copy it needs to recover the change if it is interrupted. Check that the vault's location points at the Kopia repository itself", blobID)
		}
		if len(stored) == 0 {
			return nil, fmt.Errorf("the vault password was not changed: this Kopia vault has no %s file, which a vault made by an older Kopia version may lack, and Replicaro needs a copy of it to recover the change if it is interrupted", blobID)
		}
		shown, err := showVaultPasswordKopiaFormatBlob(ctx, repo, blobID)
		if err != nil {
			return nil, fmt.Errorf("read Kopia's %s with kopia blob show before changing the vault password: %w", blobID, err)
		}
		matching := []string{}
		for name, data := range stored {
			if bytes.Equal(data, shown) {
				matching = append(matching, name)
			}
		}
		if len(matching) > 1 {
			return nil, fmt.Errorf("the vault password was not changed: the vault's storage holds the same %s under two names, so Replicaro can't tell which one Kopia uses and has no copy it could rely on to recover the change if it is interrupted", blobID)
		}
		if len(matching) == 0 {
			return nil, fmt.Errorf("the vault password was not changed: Kopia's %s read from the vault's storage doesn't match what Kopia reports, so Replicaro has no copy it could rely on to recover the change if it is interrupted", blobID)
		}
		sum := sha256.Sum256(shown)
		if blobID == engines.KopiaRepositoryBlob {
			if id, err := engines.KopiaFormatUniqueID(shown); err != nil || id != repo.NativeRepositoryID {
				return nil, errKopiaFormatChanged
			}
			saved.RepositoryName, saved.RepositorySHA256 = matching[0], hex.EncodeToString(sum[:])
		} else {
			saved.BlobcfgName, saved.BlobcfgSHA256, saved.Blobcfg = matching[0], hex.EncodeToString(sum[:]), shown
		}
	}
	return saved, nil
}

func acquireSupportedNativeProcessFence(path string) (*command.NativeProcessFence, error) {
	fence, err := command.AcquireNativeProcessFence(path)
	if err != nil {
		return nil, err
	}
	if !fence.Supported() {
		_ = fence.Close()
		return nil, fmt.Errorf("native process fencing is unsupported")
	}
	return fence, nil
}

// acquireVaultPasswordFence takes the change's fence for recovery, waiting
// while an earlier native command still holds it. limit 0 waits until ctx
// ends. A missing fence file is a free fence: the app stopped before it
// launched anything, and taking the fence creates the file again.
//
// A failed take is followed by a separate check of the fence. If that check
// can't be made at all, the take's own error is returned. If it finds the
// fence free, the holder let go between the take and the check (on Linux and
// macOS any process Replicaro starts briefly carries a copy of every open
// descriptor until it execs, so a fence this process closed a moment ago can
// look held for a few milliseconds), and the fence is taken again straight
// away. Only a fence the check also finds held is waited for.
func acquireVaultPasswordFence(ctx context.Context, repositoryID, operationUUID string, limit time.Duration) (*command.NativeProcessFence, error) {
	path, err := vaultprofile.PasswordRotationFencePath(repositoryID, operationUUID)
	if err != nil {
		return nil, err
	}
	var deadline <-chan time.Time
	if limit > 0 {
		timer := time.NewTimer(limit)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		fence, acquireErr := acquireSupportedNativeProcessFence(path)
		if acquireErr == nil {
			return fence, nil
		}
		inactive, checkErr := vaultPasswordFenceInactive(path)
		if checkErr != nil {
			return nil, acquireErr
		}
		interval := vaultPasswordFenceWaitInterval
		if inactive {
			interval = 0
		}
		wait := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			wait.Stop()
			return nil, fmt.Errorf("%w (%w)", errEarlierPasswordCommandRunning, ctx.Err())
		case <-deadline:
			wait.Stop()
			return nil, errEarlierPasswordCommandRunning
		case <-wait.C:
		}
	}
}

// probeNativePasswordChange looks at the vault for the decision table. For
// Restic it first runs the plain `unlock`, which removes only locks Restic
// itself considers stale (such as the one a killed `key passwd` leaves);
// without it every probe of a vault with that lock fails. Restic's own exit
// codes keep the probes honest: 12 is a password that opens no key, 11 a lock
// that is still live (another computer at work), and anything else is an
// error that stops this attempt rather than being read as "doesn't open".
// Kopia gives no such code, so any failed Kopia probe counts as "doesn't
// open"; that can only ever turn into a rerun or rollback when the old
// password does open, which shows Kopia's format blob was never rewritten.
//
// When neither password opens a Kopia vault, the split state is undone first
// (restoreSplitKopiaBlobcfg) and the old password probed again. When the new
// password opens a Kopia vault, or after such a write-back, Kopia's cached
// copies of the format blobs in the vault's own cache folder are dropped, so
// the checks and commands that follow read the format from storage instead of
// a stale cached one.
//
// While a rollback is in progress no unlock or probe runs: the rollback itself
// never touches the repository, and the attempt that decided to roll back had
// already removed any stale lock.
//
// The unlock also runs right after a `key passwd` in this process that
// reported success. Pinned Restic 0.19.1 can finish `key passwd` with exit 0
// while failing to remove its own lock (it only warns "error while
// unlocking"); without the unlock the candidate probe would then fail with
// exit 11 and leave a finished change waiting for a Retry.
func probeNativePasswordChange(ctx context.Context, repo models.Repository, native *recordedNativeRecovery) (nativePasswordProbe, error) {
	if native.record.RollingBack {
		return nativePasswordProbe{committedOpens: true}, nil
	}
	if repo.Engine == engines.ResticID {
		if err := unlockStaleResticLocks(ctx, repo, native.fence); err != nil {
			return nativePasswordProbe{}, err
		}
	}
	forgetCachedKopiaFormat := func() error {
		if repo.Engine != engines.KopiaID {
			return nil
		}
		if err := forgetVaultPasswordKopiaCachedFormat(repo); err != nil {
			return fmt.Errorf("clear Kopia's cached repository format: %w", err)
		}
		return nil
	}
	opens := func(password string) (bool, error) {
		err := probeVaultPassword(ctx, repo, password)
		if err == nil {
			return true, nil
		}
		if repo.Engine != engines.ResticID {
			return false, nil
		}
		switch code, ok := engines.ResticExitCode(err); {
		case ok && code == engines.ResticExitWrongPassword:
			return false, nil
		case ok && code == engines.ResticExitLocked:
			return false, errResticLiveLock
		default:
			return false, fmt.Errorf("check which vault password opens the Restic repository: %w", err)
		}
	}
	candidate, err := opens(repo.PendingPassphrase)
	if err == nil && candidate {
		err = forgetCachedKopiaFormat()
	}
	if err != nil || candidate {
		return nativePasswordProbe{candidateOpens: candidate}, err
	}
	committed, err := opens(repo.Passphrase)
	if err != nil || committed || repo.Engine != engines.KopiaID || native.record.Kopia == nil {
		return nativePasswordProbe{committedOpens: committed}, err
	}
	restored, err := restoreSplitKopiaBlobcfg(ctx, repo, *native.record.Kopia)
	if restored {
		native.restoredBlobcfg = true
	}
	if err != nil && ctx.Err() != nil && errors.Is(err, errKopiaBlobcfgRestoreFailed) {
		// The write or the read-back after it ran out of time. Whether or not
		// the bytes landed, the next attempt reads both blobs again and either
		// finds the saved pair or writes it back, so this stays resumable.
		if restored {
			return nativePasswordProbe{}, fmt.Errorf("read back Kopia's kopia.blobcfg after putting it back: %w", ctx.Err())
		}
		return nativePasswordProbe{}, fmt.Errorf("put back Kopia's kopia.blobcfg: %w", ctx.Err())
	}
	if err != nil || !restored {
		return nativePasswordProbe{}, err
	}
	if committed, _ = opens(repo.Passphrase); !committed {
		if ctx.Err() != nil {
			// The checks ran out of time after the write: the next attempt
			// finds the saved pair and goes on from there.
			return nativePasswordProbe{}, fmt.Errorf("check the current vault password after putting back Kopia's kopia.blobcfg: %w", ctx.Err())
		}
		return nativePasswordProbe{}, fmt.Errorf("%w: the current vault password still doesn't open the vault", errKopiaBlobcfgRestoreFailed)
	}
	return nativePasswordProbe{committedOpens: true}, forgetCachedKopiaFormat()
}

// restoreSplitKopiaBlobcfg undoes the one state an interrupted Kopia
// `repository change-password` leaves that neither password opens, and
// reports whether it wrote anything, also when the read-back after the write
// fails. It writes the saved kopia.blobcfg back only when all of this holds,
// and in every other case writes nothing:
//
//   - neither password opens the vault (the caller checked);
//   - kopia.repository is still byte for byte the one saved before the first
//     launch (its SHA-256 matches), so the format the old password opens is
//     intact; and
//   - kopia.blobcfg is no longer the saved one (or is gone), so Kopia already
//     rewrote it.
//
// The saved pair is what the old password opened before the change,
// so putting kopia.blobcfg back returns the vault to the state of a command
// cut off before its first write, which the decision table already handles.
// Only bytes Kopia itself wrote are copied; nothing is encrypted here.
//
// The rule guards itself. If a Kopia version wrote kopia.repository first,
// the hash would no longer match in the split state and nothing would be
// written; a finished change rewrote kopia.repository too and is never
// touched, even when both probes fail for an unrelated reason. Recovery only
// gets here holding the change's native-process fence, so the interrupted
// command has stopped and can't write kopia.repository between this check
// and the write; the vault lock and this change's sidecar fences keep this
// computer's other operations and other installations' administration out.
// Another Kopia client changing the format at the same moment is part of the
// accepted multi-computer race.
//
// On an S3 bucket with Object Lock the written-back kopia.blobcfg carries no
// retention until Kopia rewrites both blobs on the rerun; only a split
// followed by a definite failure, which rolls the change back without a
// rerun, leaves it unlocked.
func restoreSplitKopiaBlobcfg(ctx context.Context, repo models.Repository, saved vaultprofile.PasswordRotationKopiaFormat) (bool, error) {
	repository, found, err := readVaultPasswordKopiaFormatBlob(ctx, repo, saved.RepositoryName)
	if err != nil {
		return false, fmt.Errorf("read Kopia's kopia.repository to check for an interrupted password change: %w", err)
	}
	sum := sha256.Sum256(repository)
	if !found || hex.EncodeToString(sum[:]) != saved.RepositorySHA256 {
		return false, nil
	}
	blobcfg, found, err := readVaultPasswordKopiaFormatBlob(ctx, repo, saved.BlobcfgName)
	if err != nil {
		return false, fmt.Errorf("read Kopia's kopia.blobcfg to check for an interrupted password change: %w", err)
	}
	if found && bytes.Equal(blobcfg, saved.Blobcfg) {
		return false, nil
	}
	written, err := restoreVaultPasswordKopiaBlobcfg(ctx, repo, saved.BlobcfgName, saved.Blobcfg)
	if written {
		log.Printf("vault-password recovery %s put back the saved Kopia kopia.blobcfg after an interrupted password change", repo.ID)
	}
	if err != nil {
		return written, fmt.Errorf("%w: %w", errKopiaBlobcfgRestoreFailed, err)
	}
	return true, nil
}

// unlockStaleResticLocks runs `unlock` with the candidate and, if Restic
// says that password opens no key, with the committed password. Restic
// decides what is stale; Replicaro never removes a lock itself.
func unlockStaleResticLocks(ctx context.Context, repo models.Repository, fence *command.NativeProcessFence) error {
	fenced := command.WithNativeProcessFence(ctx, fence)
	for _, password := range []string{repo.PendingPassphrase, repo.Passphrase} {
		attempt := repo
		attempt.Passphrase = password
		err := unlockVaultPasswordRestic(fenced, attempt)
		if err == nil {
			return nil
		}
		if code, ok := engines.ResticExitCode(err); ok && code == engines.ResticExitWrongPassword {
			continue
		}
		return fmt.Errorf("remove stale Restic locks before checking the vault passwords: %w", err)
	}
	// Neither password opens a key; the probes report that.
	return nil
}

// launchNativePasswordChange runs the native password command once with the
// change's fence and, for Restic, the recorded key hint, and saves its
// result. The fault hooks mark where a crash leaves the result unsaved.
func launchNativePasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (database.VaultPasswordChangeOperation, VaultPasswordChangeResult, error) {
	notStarted := func(cause error) (database.VaultPasswordChangeOperation, VaultPasswordChangeResult, error) {
		if persistErr := database.RecordVaultPasswordNativeResult(db, repo.ID, "not_started", string(engines.PasswordMutationUnknown), "", cause.Error()); persistErr != nil {
			return operation, passwordChangeResult(repo, operation), fmt.Errorf("%v; persist native not-started result: %w", cause, persistErr)
		}
		updated, err := database.VaultPasswordChange(db, repo.ID)
		if err != nil {
			return operation, passwordChangeResult(repo, operation), err
		}
		return updated, passwordChangeResult(repo, updated), nil
	}
	engine, err := resolveVaultPasswordEngine(repo)
	if err != nil {
		return notStarted(err)
	}
	nativeInputPath := ""
	if repo.Engine == engines.ResticID {
		nativeInputPath, err = vaultprofile.WritePasswordRotationNativeInput(repo.ID, operation.OperationUUID, repo.PendingPassphrase)
		if err != nil {
			return notStarted(fmt.Errorf("prepare native password input: %w", err))
		}
	}
	nativeContext := command.WithNativeProcessFence(ctx, native.fence)
	if native.record.ResticKeyID != "" {
		nativeContext = engines.ContextWithResticKeyHint(nativeContext, native.record.ResticKeyID)
	}
	result, nativeErr := runNativeVaultPasswordChange(nativeContext, engine, repo, repo.PendingPassphrase, operation.OperationUUID, nativeInputPath)
	native.launched = true
	if err := vaultPasswordChangeFault("native_launched"); err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	updated, persisted, err := persistRunLocalNativePasswordResult(db, repo, operation, result, nativeErr)
	if err != nil {
		return operation, persisted, err
	}
	if err := vaultPasswordChangeFault("native_result_persisted"); err != nil {
		return updated, persisted, err
	}
	return updated, persisted, nil
}

// rerunNativePasswordChange starts the native command again after an
// interruption that left only the old password opening the vault. It
// repeats the check made before the first launch (the fenced protected
// metadata still matches the staged copy and this computer still owns the
// change), then saves the raised rerun count, and only then clears the
// recorded result and launches. In that order a crash anywhere leaves a
// count that already includes this rerun.
func rerunNativePasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (database.VaultPasswordChangeOperation, VaultPasswordChangeResult, error) {
	store := (vaultprofile.Store{Repository: repo})
	staged, err := loadVaultPasswordStage(repo.ID, operation.OperationUUID)
	if err != nil {
		return operation, passwordChangeResult(repo, operation), fmt.Errorf("durable password-change staging is unavailable: %w", err)
	}
	current, err := captureVaultPasswordRerunInventory(ctx, store, operation.OperationUUID)
	if err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	if !vaultprofile.PasswordRotationInventoriesEqual(staged, current) {
		return operation, passwordChangeResult(repo, operation), errPasswordChangeRerunMetadata
	}
	if err := assertVaultPasswordChangeAuthority(ctx, store, repo, operation, false, true); err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	next := native.record
	next.Reruns++
	if err := writeVaultPasswordRecord(next); err != nil {
		return operation, passwordChangeResult(repo, operation), fmt.Errorf("save the password change's rerun count: %w", err)
	}
	native.record = next
	if err := vaultPasswordChangeFault("rerun_count_saved"); err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	if err := database.ResetVaultPasswordNativeResultForRerun(db, repo.ID, operation.OperationUUID); err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	reset, err := database.VaultPasswordChange(db, repo.ID)
	if err != nil {
		return operation, passwordChangeResult(repo, operation), err
	}
	return launchNativePasswordChange(ctx, db, repo, reset, native)
}

// removeReplacedResticKey finishes what an interrupted `key passwd` left
// undone when the new key was written but the old one not yet removed: it
// lists the keys with the new password and removes the recorded old key, and
// nothing else, if it is still there. A reported success already removed it.
// A failure doesn't stop the change, since the new password works; the result
// then says that the old password still opens the vault.
func removeReplacedResticKey(ctx context.Context, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) string {
	if repo.Engine != engines.ResticID || native.record.ResticKeyID == "" || operation.NativeStatus == "succeeded" {
		return ""
	}
	candidate := repo
	candidate.Passphrase = repo.PendingPassphrase
	fenced := command.WithNativeProcessFence(ctx, native.fence)
	current, ids, err := listVaultPasswordResticKeys(fenced, candidate)
	if err == nil && current == native.record.ResticKeyID {
		err = fmt.Errorf("the new password opened the replaced key")
	}
	if err == nil && !slices.Contains(ids, native.record.ResticKeyID) {
		return ""
	}
	if err == nil {
		err = removeVaultPasswordResticKey(fenced, candidate, native.record.ResticKeyID)
	}
	if err != nil {
		log.Printf("vault-password recovery %s could not remove the replaced Restic key: %v", repo.ID, err)
		return resticOldKeyRemainsNote
	}
	return ""
}

// continueRecordedNativePasswordChange acts on the decision table until the
// change moves forward to publishing (done is false) or this attempt ends
// (done is true). At most one native launch happens per attempt, counting the
// first launch made by the same call.
func continueRecordedNativePasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (updated database.VaultPasswordChangeOperation, note string, result VaultPasswordChangeResult, done bool, err error) {
	for {
		if native.record.RollingBack {
			result, err = rollbackRecordedPasswordChange(ctx, db, repo, operation, native)
			return operation, "", result, true, err
		}
		if native.probe == nil {
			probe, probeErr := probeNativePasswordChange(ctx, repo, native)
			if probeErr != nil {
				return operation, "", passwordChangeResult(repo, operation), true, probeErr
			}
			native.probe = &probe
		}
		switch decideRecordedNativePassword(operation.NativeStatus, native.record.Reruns, *native.probe) {
		case recordedNativeForward:
			note = removeReplacedResticKey(ctx, repo, operation, native)
			if err := database.AdvanceVaultPasswordChangeAfterCandidateVerification(db, repo.ID, operation.OperationUUID); err != nil {
				return operation, note, passwordChangeResult(repo, operation), true, err
			}
			advanced, err := database.VaultPasswordChange(db, repo.ID)
			if err != nil {
				return operation, note, passwordChangeResult(repo, operation), true, err
			}
			return advanced, note, VaultPasswordChangeResult{}, false, nil
		case recordedNativeRerun:
			if native.launched {
				return operation, "", passwordChangeResult(repo, operation), true, errPasswordCommandInterrupted
			}
			rerun, rerunResult, rerunErr := rerunNativePasswordChange(ctx, db, repo, operation, native)
			operation = rerun
			if rerunErr != nil {
				return operation, "", rerunResult, true, rerunErr
			}
			native.probe = nil
		case recordedNativeRollback:
			result, err = rollbackRecordedPasswordChange(ctx, db, repo, operation, native)
			return operation, "", result, true, err
		default:
			if native.probe.committedOpens {
				return operation, "", passwordChangeResult(repo, operation), true, errReportedSuccessNotVisible
			}
			return operation, "", passwordChangeResult(repo, operation), true, errNeitherVaultPasswordOpens
		}
	}
}

// rollbackRecordedPasswordChange puts the vault back as it was before the
// change, once the native command stopped and only the old password opens
// it. Every step can be interrupted and resumes from where it stopped:
//
//  1. The rollback flag is saved in the record before anything remote
//     changes. From then on the checks before recovery accept the vault
//     with only some of its fences removed, and recovery only continues the
//     rollback.
//  2. Pending objects of this change go, then the profile fences, then the
//     root fence: the root keeps blocking other computers' administration
//     until every profile is clean.
//  3. Local staging goes, all but the record.
//  4. The database row and the pending candidate go.
//  5. The record goes last. A record left behind after step 4 does nothing,
//     since recovery only starts from a row.
func rollbackRecordedPasswordChange(ctx context.Context, db *sql.DB, repo models.Repository, operation database.VaultPasswordChangeOperation, native *recordedNativeRecovery) (VaultPasswordChangeResult, error) {
	if !native.record.RollingBack {
		next := native.record
		next.RollingBack = true
		if err := writeVaultPasswordRecord(next); err != nil {
			return passwordChangeResult(repo, operation), fmt.Errorf("save the password change's rollback: %w", err)
		}
		native.record = next
		if err := vaultPasswordChangeFault("rollback_flag_saved"); err != nil {
			return passwordChangeResult(repo, operation), err
		}
	}
	if err := rollbackPasswordChangeRemoteFences(ctx, repo, operation); err != nil {
		return passwordChangeResult(repo, operation), err
	}
	if err := cleanupVaultPasswordStageKeepingRecord(repo.ID, operation.OperationUUID); err != nil {
		return passwordChangeResult(repo, operation), err
	}
	if err := vaultPasswordChangeFault("rollback_stage_cleaned"); err != nil {
		return passwordChangeResult(repo, operation), err
	}
	if err := abandonRolledBackVaultPasswordChange(db, repo.ID, operation.OperationUUID); err != nil {
		return passwordChangeResult(repo, operation), err
	}
	if err := vaultPasswordChangeFault("rollback_row_abandoned"); err != nil {
		return passwordChangeResult(repo, operation), err
	}
	if err := cleanupVaultPasswordStage(repo.ID, operation.OperationUUID); err != nil {
		// The change is already rolled back; only an inert record is left.
		log.Printf("vault-password rollback %s left its recovery record: %v", repo.ID, err)
	}
	return rolledBackPasswordChangeResult(repo, operation, native.record.Reruns)
}

// notStartedPasswordChangeMessage reports a first launch that never started.
// The callers return no error for this case, so startup recovery still
// finishes the operation as interrupted, and the saved cause goes into the
// message instead so the user can see why the command couldn't start.
func notStartedPasswordChangeMessage(lastError string) string {
	const message = "Vault-password change did not start and its remote fence was removed"
	if lastError == "" {
		return message + "."
	}
	return message + ": " + strings.TrimSuffix(lastError, ".") + "."
}

// rolledBackPasswordChangeResult reports a finished rollback with the native
// result that caused it.
//
// A not_started result with reruns counted comes from a rerun that couldn't
// be launched: a first launch that doesn't start is rolled back straight
// away and never has a rerun counted. That is a failure of this attempt, not
// a change the restart cut off, so it is reported with its cause as an
// error, which also keeps startup recovery from finishing the operation as
// interrupted.
func rolledBackPasswordChangeResult(repo models.Repository, operation database.VaultPasswordChangeOperation, reruns int) (VaultPasswordChangeResult, error) {
	result := passwordChangeResult(repo, operation)
	result.CleanupPending = false
	result.SidecarStatus = "not_changed"
	switch {
	case operation.NativeStatus == "not_started" && reruns > 0 && operation.LastError != "":
		result.Phase = "failed"
		result.Message = "The vault keeps its current password. The protected recovery metadata was left unchanged, and this change's fences and staging were removed."
		return result, errors.New(operation.LastError)
	case operation.NativeStatus == "not_started":
		result.Phase = "not_started"
		result.Message = notStartedPasswordChangeMessage(operation.LastError)
		return result, nil
	case operation.NativeMutationDisposition == string(engines.PasswordMutationRejectedBeforeMutation):
		result.Phase = "failed"
		result.Message = "Restic rejected the password change because the repository was locked before mutation. The protected recovery metadata and committed password were left unchanged, and this operation's fence and staging were removed."
		if operation.LastError != "" {
			return result, errors.New(operation.LastError)
		}
		return result, fmt.Errorf("native Restic password change was rejected before mutation")
	case operation.NativeStatus == "failed":
		result.Phase = "failed"
		result.Message = "The vault keeps its current password. The protected recovery metadata was left unchanged, and this change's fences and staging were removed."
		if operation.LastError != "" {
			return result, errors.New(operation.LastError)
		}
		return result, fmt.Errorf("the native vault password command failed")
	default:
		result.Phase = "failed"
		result.Message = "The vault keeps its current password. The protected recovery metadata was left unchanged, and this change's fences and staging were removed."
		return result, errPasswordCommandInterruptedRepeatedly
	}
}
