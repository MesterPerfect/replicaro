package artifactrecovery

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/local/replicaro/database"
	"github.com/local/replicaro/engines"
)

// Reconcile resolves crash-interrupted Restic/Kopia artifact stages before any
// worker or API endpoint can use repository credentials. A saved change whose
// old copy still can't be removed is logged as an issue and does not fail it;
// the quarantined copy sits beside the vault's own folder and is never read.
func Reconcile(db *sql.DB) error {
	stages, legacy, scanErr := engines.PendingRepositoryArtifactStages()
	var errs []error
	if scanErr != nil {
		errs = append(errs, scanErr)
	}
	for _, item := range legacy {
		message := "Legacy local engine artifact quarantine requires manual cleanup: " + bounded(item, 160)
		if err := database.LogError(db, message); err != nil {
			errs = append(errs, fmt.Errorf("record legacy artifact quarantine: %w", err))
		}
	}
	for _, stage := range stages {
		committed, err := reconcileStage(db, stage)
		if err == nil {
			continue
		}
		manifest := stage.Manifest()
		if committed {
			// The vault change behind this stage is already saved, so the only
			// thing left is deleting the old copy. That happens when the
			// request itself reported "completed with issues" because the
			// removal failed, or when the app stopped between saving the
			// change and removing the old copy. Either way it must not stop
			// the app: it becomes a dashboard issue naming the leftover
			// folder. Finalize marked the manifest as saved before trying, so
			// it stays, and the next start removes the folder without looking
			// at the database again; the issue stops once the folder is gone,
			// whether a later attempt removed it or the user did. Dropping the
			// manifest instead would only turn the folder into an anonymous
			// quarantine that is reported on every start and never removed.
			// Everything else here (an unreadable manifest, an engine
			// mismatch, a failed restore of an unsaved change) stays fatal,
			// because guessing could put the wrong credentials back in place.
			log.Printf("remove quarantined local %s engine artifacts for repository %s: %v", manifest.Engine, manifest.RepositoryID, err)
			message := fmt.Sprintf("Quarantined old local %s engine artifacts for repository %s could not be removed and require manual cleanup: %s in the Replicaro data folder",
				manifest.Engine, bounded(manifest.RepositoryID, 80),
				filepath.Join("engines", manifest.Engine, bounded(manifest.Quarantine, 80)))
			if logErr := database.LogWarning(db, message); logErr != nil {
				errs = append(errs, fmt.Errorf("record leftover engine artifact cleanup: %w", logErr))
			}
			continue
		}
		message := fmt.Sprintf("Local %s artifact recovery for repository %s requires attention", manifest.Engine, bounded(manifest.RepositoryID, 80))
		_ = database.LogError(db, message)
		errs = append(errs, fmt.Errorf("%s: %w", message, err))
	}
	return errors.Join(errs...)
}

// finalizeStage is replaced in tests to make the removal fail.
var finalizeStage = (*engines.RepositoryArtifactStage).Finalize

// reconcileStage finalizes a stage whose change was saved and restores one
// whose change was not. committed reports that the change was saved, so a
// returned error came from removing the quarantined old copy.
func reconcileStage(db *sql.DB, stage *engines.RepositoryArtifactStage) (committed bool, err error) {
	manifest := stage.Manifest()
	// Finalize marks a manifest once the change is saved. Don't classify a
	// marked manifest from the database again: by now the same vault may be
	// back under the same ID, or its credentials back to the old values, and
	// either would make the saved change look unsaved and move the old copy
	// over the current one.
	if manifest.Committed {
		return true, finalizeStage(stage)
	}
	repo, err := database.GetRepository(db, manifest.RepositoryID)
	present := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if present && repo.Engine != manifest.Engine {
		return false, fmt.Errorf("repository engine does not match recovery manifest")
	}

	committed = !present
	if present && manifest.Action == engines.RepositoryArtifactCredentialRotation {
		digest, digestErr := engines.RepositoryOptionsDigest(repo)
		if digestErr != nil {
			return false, digestErr
		}
		committed = digest != manifest.OldOptionsSHA256
	}

	// Stage methods inspect original/quarantine collision states and refuse an
	// unsafe overwrite. A committed mutation always discards only quarantine.
	if committed {
		return true, finalizeStage(stage)
	}
	return false, stage.Restore()
}

func bounded(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
