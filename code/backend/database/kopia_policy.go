package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/models"
)

var ErrKopiaPolicyNotReady = errors.New("Kopia policy reconciliation is not ready")
var ErrKopiaPolicyRetryUnavailable = errors.New("Kopia policy reconciliation is not in an error state")

// ErrKopiaPolicyFenceHeld means the process of an earlier policy application
// still holds its fence, so no new policy command may start yet.
var ErrKopiaPolicyFenceHeld = errors.New("prior Kopia policy process is not proven inactive")

// KopiaPolicyStuckAfter is how long the process of an earlier policy
// application may keep its fence before the vault gets a dashboard issue. It
// matches the reconnect escalation, which leaves a held fence out on purpose:
// a stuck process is not something reconnecting fixes.
const KopiaPolicyStuckAfter = 6 * time.Hour

// StuckKopiaPolicy is a Kopia vault whose policy application is parked
// behind a fence the earlier process has held for KopiaPolicyStuckAfter.
type StuckKopiaPolicy struct {
	RepositoryID string
	Name         string
	// StuckAt is when the fence had been held for KopiaPolicyStuckAfter.
	StuckAt time.Time
}

// kopiaPolicyFenceInactive is replaced in tests.
var kopiaPolicyFenceInactive = command.NativeProcessFenceInactive

// StuckKopiaPolicies lists the Kopia vaults whose policy reconciler found the
// earlier policy process still holding its fence (ErrKopiaPolicyFenceHeld)
// and whose fence has been held for more than KopiaPolicyStuckAfter. The age
// comes from the fence file, which is created when the process starts, so no
// extra state is kept. The fence is checked again here, so the issue goes away
// as soon as the process ends, before the reconciler's next retry clears the
// row. A fence that can't be read or checked is left out.
func StuckKopiaPolicies(db queryer, now time.Time) ([]StuckKopiaPolicy, error) {
	rows, err := db.Query(`SELECT k.repository_id, r.name, k.active_fence_path
		FROM kopia_policy_state k JOIN repositories r ON r.id = k.repository_id
		WHERE k.state = 'error' AND k.active_fence_path != '' AND k.last_error = ?
		ORDER BY k.repository_id`, ErrKopiaPolicyFenceHeld.Error())
	if err != nil {
		return nil, err
	}
	type held struct{ id, name, fence string }
	var candidates []held
	for rows.Next() {
		var row held
		if err := rows.Scan(&row.id, &row.name, &row.fence); err != nil {
			_ = rows.Close()
			return nil, err
		}
		candidates = append(candidates, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var stuck []StuckKopiaPolicy
	for _, row := range candidates {
		info, err := os.Stat(row.fence)
		if err != nil || now.Sub(info.ModTime()) <= KopiaPolicyStuckAfter {
			continue
		}
		if inactive, err := kopiaPolicyFenceInactive(row.fence); err != nil || inactive {
			continue
		}
		stuck = append(stuck, StuckKopiaPolicy{
			RepositoryID: row.id, Name: row.name, StuckAt: info.ModTime().Add(KopiaPolicyStuckAfter),
		})
	}
	return stuck, nil
}

type KopiaPolicyState struct {
	RepositoryID     string
	DesiredDigest    string
	AppliedDigest    string
	State            string
	LastError        string
	LastReconciledAt string
	ActiveFencePath  string
	ProofKind        string
}

type queryer interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func DeriveKopiaPolicyDesired(db queryer, repositoryID string) (engines.KopiaManagedPolicyDesiredState, error) {
	var engine, connector, maintenanceSchedule, objectLockJSON string
	if err := db.QueryRow(`SELECT engine,connector,maintenance_schedule,object_lock_json FROM repositories WHERE id=?`, repositoryID).
		Scan(&engine, &connector, &maintenanceSchedule, &objectLockJSON); err != nil {
		return engines.KopiaManagedPolicyDesiredState{}, err
	}
	if engine != engines.KopiaID {
		return engines.KopiaManagedPolicyDesiredState{}, fmt.Errorf("repository is not a Kopia vault")
	}
	rows, err := db.Query(`
		SELECT j.id,j.source,j.excludes,j.retention,j.retention_hourly,
		       j.retention_daily,j.retention_weekly,j.retention_monthly,j.retention_yearly,
		       j.skip_nobackup_folders,j.skip_marker_file_name
		FROM backup_jobs j
		JOIN backup_job_targets t ON t.job_id=j.id
		WHERE t.repository_id=?
		ORDER BY j.id`, repositoryID)
	if err != nil {
		return engines.KopiaManagedPolicyDesiredState{}, err
	}
	defer rows.Close()
	var objectLock models.ObjectLockSettings
	if err := json.Unmarshal([]byte(objectLockJSON), &objectLock); err != nil {
		return engines.KopiaManagedPolicyDesiredState{}, fmt.Errorf("decode Kopia object lock settings: %w", err)
	}
	objectLock, err = models.NormalizeObjectLock(engine, connector, objectLock)
	if err != nil {
		return engines.KopiaManagedPolicyDesiredState{}, err
	}
	desired := engines.KopiaManagedPolicyDesiredState{Version: 1,
		MaintenanceSchedule: maintenanceSchedule, ObjectLock: objectLock}
	for rows.Next() {
		var jobUUID, source, exclusions, markerName string
		var latest int
		var hourly, daily, weekly, monthly, yearly sql.NullInt64
		var skipNoBackup bool
		if err := rows.Scan(&jobUUID, &source, &exclusions, &latest, &hourly,
			&daily, &weekly, &monthly, &yearly, &skipNoBackup, &markerName); err != nil {
			return engines.KopiaManagedPolicyDesiredState{}, err
		}
		// .kopiaignore is always listed (the box is locked on for Kopia
		// vaults), and the CACHEDIR.TAG box needs nothing here: every managed
		// job policy sets ignoreCacheDirs.
		dotIgnore := []string{models.KopiaIgnoreFileName}
		if skipNoBackup {
			dotIgnore = append(dotIgnore, models.NoBackupMarkerFile)
		}
		if markerName != "" {
			dotIgnore = append(dotIgnore, markerName)
		}
		value := func(field sql.NullInt64) int {
			if latest == 0 || !field.Valid {
				return 0
			}
			return int(field.Int64)
		}
		desired.Sources = append(desired.Sources, engines.KopiaManagedPolicySource{
			JobUUID: jobUUID, Source: source, Excludes: strings.Split(exclusions, "\n"), DotIgnore: dotIgnore,
			KeepLatest: latest, KeepHourly: value(hourly), KeepDaily: value(daily),
			KeepWeekly: value(weekly), KeepMonthly: value(monthly), KeepAnnual: value(yearly),
		})
	}
	if err := rows.Err(); err != nil {
		return engines.KopiaManagedPolicyDesiredState{}, err
	}
	return engines.NormalizeKopiaManagedPolicyDesired(desired)
}

func RefreshKopiaPolicyStatesTx(tx *sql.Tx, repositoryIDs []string) ([]string, error) {
	ids := uniqueSorted(repositoryIDs)
	changed := []string{}
	for _, repositoryID := range ids {
		var engine string
		err := tx.QueryRow(`SELECT engine FROM repositories WHERE id=?`, repositoryID).Scan(&engine)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if engine != engines.KopiaID {
			continue
		}
		desired, err := DeriveKopiaPolicyDesired(tx, repositoryID)
		if err != nil {
			return nil, err
		}
		digest, err := engines.KopiaManagedPolicyDigest(desired)
		if err != nil {
			return nil, err
		}
		var prior string
		err = tx.QueryRow(`SELECT desired_digest FROM kopia_policy_state WHERE repository_id=?`, repositoryID).Scan(&prior)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.Exec(`INSERT INTO kopia_policy_state
				(repository_id,desired_digest,applied_digest,state)
				VALUES (?,?,'','dirty')`, repositoryID, digest); err != nil {
				return nil, err
			}
			changed = append(changed, repositoryID)
		case err != nil:
			return nil, err
		case prior != digest:
			if _, err := tx.Exec(`UPDATE kopia_policy_state
				SET desired_digest=?,
					state=CASE WHEN active_fence_path<>'' THEN 'applying' ELSE 'dirty' END,
					last_error=CASE WHEN active_fence_path<>'' THEN last_error ELSE '' END,
					active_fence_path=CASE WHEN active_fence_path<>'' THEN active_fence_path ELSE '' END,
					proof_kind=CASE WHEN active_fence_path<>'' THEN proof_kind ELSE '' END
				WHERE repository_id=?`, digest, repositoryID); err != nil {
				return nil, err
			}
			changed = append(changed, repositoryID)
		}
	}
	return changed, nil
}

// MarkAllKopiaPoliciesVerificationRequired synchronously removes startup
// readiness before schedulers or API handlers can admit Kopia backups.
// An in-progress row retains its durable native-process fence so recovery can
// prove the prior process inactive before any new mutation.
func MarkAllKopiaPoliciesVerificationRequired(db *sql.DB) ([]string, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT id FROM repositories WHERE engine='kopia' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	for _, id := range ids {
		desired, err := DeriveKopiaPolicyDesired(tx, id)
		if err != nil {
			return nil, err
		}
		digest, err := engines.KopiaManagedPolicyDigest(desired)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO kopia_policy_state
			(repository_id,desired_digest,applied_digest,state)
			VALUES (?,?,'','dirty')
			ON CONFLICT(repository_id) DO UPDATE SET
				desired_digest=excluded.desired_digest,
				state=CASE WHEN kopia_policy_state.active_fence_path<>'' THEN 'applying' ELSE 'dirty' END,
				last_error=CASE WHEN kopia_policy_state.active_fence_path<>''
					THEN kopia_policy_state.last_error ELSE '' END,
				active_fence_path=CASE WHEN kopia_policy_state.active_fence_path<>''
					THEN kopia_policy_state.active_fence_path ELSE '' END,
				proof_kind=CASE WHEN kopia_policy_state.active_fence_path<>''
					THEN kopia_policy_state.proof_kind ELSE '' END`,
			id, digest); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

func InitializeKopiaPolicyStateTx(tx *sql.Tx, repositoryID, digest string, ready bool) error {
	if len(digest) != 64 {
		return fmt.Errorf("Kopia desired digest is invalid")
	}
	state, applied := "dirty", ""
	if ready {
		state, applied = "ready", digest
	}
	_, err := tx.Exec(`INSERT INTO kopia_policy_state
		(repository_id,desired_digest,applied_digest,state,last_error,last_reconciled_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(repository_id) DO UPDATE SET
			desired_digest=excluded.desired_digest,
			applied_digest=excluded.applied_digest,
			state=excluded.state,
			last_error='',
			last_reconciled_at=excluded.last_reconciled_at,
			active_fence_path='',
			proof_kind=''`,
		repositoryID, digest, applied, state, "",
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func GetKopiaPolicyState(db *sql.DB, repositoryID string) (KopiaPolicyState, error) {
	return getKopiaPolicyState(db, repositoryID)
}

func getKopiaPolicyState(db queryer, repositoryID string) (KopiaPolicyState, error) {
	var value KopiaPolicyState
	err := db.QueryRow(`SELECT repository_id,desired_digest,applied_digest,state,
		last_error,last_reconciled_at,active_fence_path,proof_kind
		FROM kopia_policy_state WHERE repository_id=?`, repositoryID).Scan(
		&value.RepositoryID, &value.DesiredDigest, &value.AppliedDigest, &value.State,
		&value.LastError, &value.LastReconciledAt, &value.ActiveFencePath, &value.ProofKind)
	return value, err
}

func RequireKopiaPolicyReady(db *sql.DB, repositoryID string) error {
	return requireKopiaPolicyReady(db, repositoryID)
}

// MarkKopiaPolicyVerificationRequired closes backup admission before an exact
// managed-policy cleanup can expose snapshots to a different inheritance path.
// An active durable fence is never displaced by this local transition.
func MarkKopiaPolicyVerificationRequired(db *sql.DB, repositoryID string) error {
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='dirty',applied_digest='',last_error=''
		WHERE repository_id=? AND state<>'applying' AND active_fence_path=''`, repositoryID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("%w: policy verification cannot be closed while reconciliation is active", ErrKopiaPolicyNotReady)
	}
	return nil
}

func requireKopiaPolicyReady(db queryer, repositoryID string) error {
	var engine string
	if err := db.QueryRow(`SELECT engine FROM repositories WHERE id=?`, repositoryID).Scan(&engine); err != nil {
		return err
	}
	if engine != engines.KopiaID {
		return nil
	}
	state, err := getKopiaPolicyState(db, repositoryID)
	if err != nil {
		return fmt.Errorf("%w: state is missing", ErrKopiaPolicyNotReady)
	}
	if state.State != "ready" || state.DesiredDigest == "" || state.AppliedDigest != state.DesiredDigest {
		if state.LastError != "" {
			return fmt.Errorf("%w: %s", ErrKopiaPolicyNotReady, state.LastError)
		}
		return fmt.Errorf("%w: reconciliation is %s", ErrKopiaPolicyNotReady, state.State)
	}
	return nil
}

func BeginKopiaPolicyApplication(db *sql.DB, repositoryID, desiredDigest, fencePath, proofKind string) error {
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='applying',last_error='',active_fence_path=?,proof_kind=?
		WHERE repository_id=? AND desired_digest=? AND state<>'applying'`,
		fencePath, proofKind, repositoryID, desiredDigest)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("%w: desired state changed or another reconciliation is active", ErrKopiaPolicyNotReady)
	}
	return nil
}

func ResetInterruptedKopiaPolicyApplication(
	db *sql.DB,
	repositoryID, desiredDigest, priorFencePath string,
) error {
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='dirty',
			last_error='Application stopped before Kopia policy readback was durably recorded.',
			active_fence_path='',
			proof_kind=''
		WHERE repository_id=? AND desired_digest=? AND state IN ('applying','dirty','error')
			AND active_fence_path=?`,
		repositoryID, desiredDigest, priorFencePath)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("%w: interrupted application state changed during fence recovery", ErrKopiaPolicyNotReady)
	}
	return nil
}

func MarkKopiaPolicyFenceCleanupError(
	db *sql.DB,
	repositoryID, desiredDigest, fencePath, proofKind string,
	cleanupErr error,
) error {
	if cleanupErr == nil || fencePath == "" || proofKind == "" {
		return fmt.Errorf("Kopia fence cleanup failure is incomplete")
	}
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='error',applied_digest='',last_error=?,
			active_fence_path=?,proof_kind=?
		WHERE repository_id=? AND desired_digest=? AND state IN ('ready','dirty','error')`,
		"Native process fence cleanup failed: "+cleanupErr.Error(),
		fencePath, proofKind, repositoryID, desiredDigest)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("Kopia policy state changed before fence cleanup failure was recorded")
	}
	return nil
}

// MarkKopiaPolicyErrorKeepingFence records an error on a row that still
// carries the fence of an earlier policy application: that process still
// holds the fence, or the reconciliation that should check it failed before
// it could (the vault lock or the vault check failed). The row keeps the
// fence, like a fence cleanup error, so the reconciler's retry backoff
// decides when to look again and the retry reopens it as applying to check
// the same fence.
func MarkKopiaPolicyErrorKeepingFence(
	db *sql.DB,
	repositoryID, desiredDigest, fencePath string,
	cause error,
) error {
	if cause == nil || fencePath == "" {
		return fmt.Errorf("Kopia fence-keeping error record is incomplete")
	}
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='error',applied_digest='',last_error=?
		WHERE repository_id=? AND desired_digest=? AND active_fence_path=?
			AND state IN ('applying','dirty','error')`,
		cause.Error(), repositoryID, desiredDigest, fencePath)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("%w: policy state changed before the fence-keeping error was recorded", ErrKopiaPolicyNotReady)
	}
	return nil
}

func FinishKopiaPolicyApplication(
	db *sql.DB,
	repositoryID, desiredDigest string,
	reconcileErr error,
	preserveVerifiedReadiness bool,
	mutationStarted bool,
	driftObserved bool,
) error {
	state, applied, lastError := "ready", desiredDigest, ""
	if reconcileErr != nil {
		if preserveVerifiedReadiness && !mutationStarted && !driftObserved {
			state, applied = "ready", desiredDigest
		} else {
			state, applied, lastError = "error", "", reconcileErr.Error()
		}
	}
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state=?,applied_digest=?,last_error=?,last_reconciled_at=?,
			active_fence_path='',proof_kind=''
		WHERE repository_id=? AND desired_digest=?`,
		state, applied, lastError, time.Now().UTC().Format(time.RFC3339Nano),
		repositoryID, desiredDigest)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("Kopia desired state changed before reconciliation completed")
	}
	return nil
}

func MarkKopiaPolicyReconciliationError(
	db *sql.DB,
	repositoryID, desiredDigest string,
	reconcileErr error,
) error {
	if reconcileErr == nil {
		return fmt.Errorf("Kopia reconciliation error is required")
	}
	result, err := db.Exec(`UPDATE kopia_policy_state
		SET state='error',applied_digest='',last_error=?,last_reconciled_at=?,
			active_fence_path='',proof_kind=''
		WHERE repository_id=? AND desired_digest=? AND state='dirty'`,
		reconcileErr.Error(), time.Now().UTC().Format(time.RFC3339Nano),
		repositoryID, desiredDigest)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("Kopia desired state changed before reconciliation error was recorded")
	}
	return nil
}

// RetryKopiaPolicyForRepository reopens the vault's policy only from its
// current error state. The reconciler's retry timer is its only caller: an
// error is retried automatically, whether or not the vault has any job target,
// and backups stay blocked until a later reconciliation proves the policy by
// readback. It never changes the desired digest.
func RetryKopiaPolicyForRepository(db *sql.DB, repositoryID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := retryKopiaPolicyForRepositoryTx(tx, repositoryID); err != nil {
		return err
	}
	return tx.Commit()
}

func retryKopiaPolicyForRepositoryTx(tx *sql.Tx, repositoryID string) error {
	var engine, state string
	if err := tx.QueryRow(`SELECT r.engine,k.state
		FROM repositories r JOIN kopia_policy_state k ON k.repository_id=r.id
		WHERE r.id=?`, repositoryID).Scan(&engine, &state); err != nil {
		return err
	}
	if engine != engines.KopiaID {
		return fmt.Errorf("repository is not a Kopia vault")
	}
	if state != "error" {
		return fmt.Errorf("%w: current state is %s", ErrKopiaPolicyRetryUnavailable, state)
	}
	// A fence-cleanup error deliberately keeps its active_fence_path. Reopen it as
	// applying, not dirty, so the manager keeps it on the interrupted-process
	// recovery path until the fence is confirmed inactive.
	result, err := tx.Exec(`UPDATE kopia_policy_state
		SET state=CASE WHEN active_fence_path<>'' THEN 'applying' ELSE 'dirty' END,
			last_error=''
		WHERE repository_id=? AND state='error'`, repositoryID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrKopiaPolicyRetryUnavailable
	}
	return nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
