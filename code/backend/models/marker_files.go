package models

import (
	"errors"
	"strings"
	"unicode"
)

// The marker files a job can skip folders by. Each engine gets its own native
// setting (see engines.BackupOptions and the Kopia managed job policy):
//
//	.nobackup     Restic --exclude-if-present .nobackup, Kopia dot-ignore file
//	CACHEDIR.TAG  Restic --exclude-caches, Kopia ignoreCacheDirs
//	custom name   Restic --exclude-if-present <name>, Kopia dot-ignore file
//	.kopiaignore  Kopia dot-ignore file only, always on for Kopia vaults
//
// The engines read these files differently, and Replicaro leaves that to
// them: Restic skips a folder whenever the file exists, while Kopia reads the
// file as ignore rules (a file containing just * skips the folder's
// contents). For CACHEDIR.TAG both engines check the signature line.
const (
	NoBackupMarkerFile  = ".nobackup"
	CacheDirMarkerFile  = "CACHEDIR.TAG"
	KopiaIgnoreFileName = ".kopiaignore"
)

// The exact error texts for the custom marker file name; the frontend shows
// translated copies of the same two messages.
var (
	ErrSkipMarkerFileName  = errors.New("Enter a file name only, without a folder, a colon (:), wildcards, or spaces at the start or end.")
	ErrSkipMarkerFileTaken = errors.New("This name already has its own option above.")
)

// ValidateSkipMarkerFileName accepts one plain file name for the custom
// marker box: no "/" or "\\" (a folder), no ":" (Restic reads "name:header"
// as a file name and a required first line), no wildcards, not "." or "..",
// no spaces at either end and no control characters. Wildcards are refused
// because neither engine expands them here: pinned Restic's
// --exclude-if-present and Kopia's dot-ignore list both look for a file with
// exactly that name, so "*.tag" would only ever match a file literally named
// "*.tag", while it reads as if it matched every .tag file. The names that
// already have their own box are refused too; CACHEDIR.TAG as a custom name
// would make Restic skip on presence alone, without the signature check. An
// empty name means the box is off.
func ValidateSkipMarkerFileName(name string) error {
	if name == "" {
		return nil
	}
	if name == "." || name == ".." || strings.TrimSpace(name) != name || strings.ContainsAny(name, `/\:*?[]{}`) {
		return ErrSkipMarkerFileName
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ErrSkipMarkerFileName
		}
	}
	switch name {
	case NoBackupMarkerFile, CacheDirMarkerFile, KopiaIgnoreFileName:
		return ErrSkipMarkerFileTaken
	}
	return nil
}

// UsesKopia reports whether the job backs up to a Kopia vault. The job's
// targets decide it, not its engine settings alone: a settings section stays
// behind when its last vault is removed, and counting it would keep the
// CACHEDIR.TAG box locked (and Restic passing --exclude-caches) against the
// user's saved choice.
//
// An attached Kopia target counts. A target this computer hasn't attached
// (the job's vault on another computer, or a job recovered from one vault
// whose other vaults aren't connected here) has no engine on record, so the
// job's own Kopia settings section stands in for it: every stored section is
// kept while the job lists such a vault (see normalizeUpdatedJobSettings in
// the api package), so a section left behind by a removed Kopia vault counts
// too in that case. That errs toward locking only when the job's records say
// Kopia. The frontend applies the same rule with the unattachedTargets field,
// so keep the two in step.
func (job BackupJob) UsesKopia() bool {
	for _, target := range job.Targets {
		if target.Engine == "kopia" {
			return true
		}
	}
	if !job.HasUnattachedTargets() {
		return false
	}
	_, ok := job.EngineSettings["kopia"]
	return ok
}

// HasUnattachedTargets reports whether the job's vault list (shared through
// the vault profile) names a vault that isn't one of its targets on this
// computer.
func (job BackupJob) HasUnattachedTargets() bool {
	for _, id := range job.PortableTargetIDs {
		attached := false
		for _, target := range job.Targets {
			if target.RepositoryID == id {
				attached = true
				break
			}
		}
		if !attached {
			return true
		}
	}
	return false
}

// SkipsCacheDirFolders is the effective CACHEDIR.TAG choice: the user's own,
// or always on while the job has a Kopia vault (see UsesKopia). Every Kopia
// job policy sets ignoreCacheDirs, and the job's Restic vaults then follow it
// so one job doesn't skip different folders per vault. The saved choice is
// never rewritten, so removing the job's last Kopia vault brings the user's
// choice back.
func (job BackupJob) SkipsCacheDirFolders() bool {
	return job.SkipCacheDirFolders || job.UsesKopia()
}
