package engines

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/local/replicaro/appdata"
)

// Private rclone configs and session folders
//
// This file holds the local file handling for Replicaro's own rclone configs:
// the per-vault rclone/vaults/<uuid>/rclone.conf, the rclone/config-sessions
// sign-in candidates and the rclone/sessions operation folders. It uses plain
// path operations on purpose:
//
//   - folders are created with os.MkdirAll(0o700); on Windows they inherit the
//     application folder's protected DACL;
//   - a config Replicaro has rclone create is set to 0600 on Unix; on Windows
//     it inherits the same protected DACL from its folder;
//   - before and after each command a config only has to exist, be a regular
//     file and be at most 8 MiB (os.Stat, so a linked folder or file is fine);
//   - publication is one os.Rename on the same filesystem, followed by a
//     directory fsync on Unix;
//   - cleanup only touches names Replicaro recognizes and uses os.RemoveAll or
//     os.Remove, which never follow links (os.RemoveAll unlinks a link instead
//     of descending into it on every supported OS).
//
// What it deliberately doesn't do: walk every path component from / refusing
// links, case-variant siblings or folders that can be entered but not listed;
// hold folder handles and compare file identities between steps; require a
// single link, the current user as owner, a particular mode or a particular
// Windows ACL on an existing config; truncate a config before deleting it; or
// refuse to sweep a stale session that holds a link or FIFO. Those checks only
// resist someone who already has access to the computer (another local
// account or software running as this user), which Replicaro doesn't defend
// against, and they reject ordinary setups: a symlinked home or ~/.config,
// ~/.config/Replicaro next to ~/.config/replicaro, a 0711 parent, a junctioned
// Windows profile, a config restored with a different umask, or an extra ACL
// entry added by backup or management software. Don't add link, owner, mode,
// case or identity checks back here without a product decision; the accidents
// this code does guard against are listed above.

// renameRcloneConfigCandidate publishes a signed-in candidate. On Windows
// os.Rename is MoveFileEx with MOVEFILE_REPLACE_EXISTING, so it replaces an
// existing config atomically, just like rename(2). Tests swap it to simulate a
// failed rename.
var renameRcloneConfigCandidate = os.Rename

// syncRcloneVaultPublicationDirectory runs right after a successful
// publication rename. Tests swap it to simulate a failed sync.
var syncRcloneVaultPublicationDirectory = syncRcloneConfigDirectory

// makePrivateRcloneDirectory creates path and any missing parents as
// owner-only folders. The umask can only clear bits, so 0o700 always ends up
// owner-only on Unix; on Windows each new folder inherits the protected DACL
// that the application folder gets when Replicaro creates it. Folders that
// already exist keep their mode, and links in the path are followed like in
// any other program.
func makePrivateRcloneDirectory(path string) error {
	return os.MkdirAll(path, 0o700)
}

// validateRcloneVaultFile checks a private rclone config before or after a
// native command: it has to exist, be a regular file and be at most 8 MiB.
// The bytes are never read here; pinned rclone owns the file's contents and
// its token refresh.
//
// A missing file or one with the wrong type maps to "reconnect required"
// through localRcloneBindingFailure; an oversized file or another I/O error is
// an ordinary failure, so a transient disk problem doesn't send the user
// through a new sign-in.
func validateRcloneVaultFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkRcloneConfigInfo(info)
}

func checkRcloneConfigInfo(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return invalidRcloneLocalBinding(fmt.Errorf("rclone vault config is not a regular file"))
	}
	if info.Size() > maximumRcloneVaultConfigBytes {
		return fmt.Errorf("rclone vault config is oversized")
	}
	return nil
}

// checkRcloneVaultConfig validates a vault's canonical config. Other files in
// the vault folder are ignored, in particular rclone's own rclone.conf<digits>
// and rclone.conf.old<digits> files: rclone writes those next to the config
// every time it saves a refreshed token, so a concurrent command or an
// interrupted save can leave them behind. Don't treat them as a broken
// config: a working vault would then need a new sign-in after any interrupted
// token refresh.
func checkRcloneVaultConfig(repositoryID string) error {
	path, err := RcloneVaultConfigPath(repositoryID)
	if err != nil {
		return err
	}
	return validateRcloneVaultFile(path)
}

// hardenNewRcloneConfigFile makes a config that Replicaro just had rclone
// create owner-only. On Unix that's mode 0600. On Windows there's nothing to
// do: the new file already inherits the protected owner, LocalSystem and
// Administrators DACL that the application folder gets when it's created.
// It's only used on new files. When rclone later saves a refreshed token it
// keeps the existing mode, and an existing config's permissions aren't
// checked or repaired before each command.
func hardenNewRcloneConfigFile(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(path, 0o600)
}

// prepareRcloneVaultDirectory creates the vault's config folder and returns
// the canonical config path inside it.
func prepareRcloneVaultDirectory(repositoryID string) (string, error) {
	config, err := RcloneVaultConfigPath(repositoryID)
	if err != nil {
		return "", err
	}
	if err := makePrivateRcloneDirectory(filepath.Dir(config)); err != nil {
		return "", fmt.Errorf("create rclone vault directory: %w", err)
	}
	return config, nil
}

// touchRcloneVaultSidecarConfig has rclone create an empty sidecar config at
// the canonical path, makes it owner-only and returns a binding for it.
func touchRcloneVaultSidecarConfig(
	ctx context.Context,
	binary, repositoryID, config, cache, temporary string,
) (*RcloneVaultConfigBinding, error) {
	if _, err := runRcloneVaultConfigCommand(
		ctx, binary,
		[]string{"config", "touch", "--config", config,
			"--cache-dir", cache, "--temp-dir", temporary,
			"--log-level", "ERROR"},
		nil, "", time.Minute, RcloneComponentID,
	); err != nil {
		return nil, err
	}
	if err := hardenNewRcloneConfigFile(config); err != nil {
		return nil, err
	}
	binding := nonResticRcloneSidecarBinding(repositoryID, config)
	if err := binding.Revalidate(ctx); err != nil {
		return nil, err
	}
	return binding, nil
}

// publishRcloneVaultConfig moves a signed-in candidate from its config-session
// folder to the vault's canonical rclone.conf in one rename. Both live under
// the same configuration root, so the rename is atomic: the vault either keeps
// its old config or gets the new one, never a partial file. A rename across
// filesystems fails before anything moves.
//
// The disposition says who owns the sign-in afterwards:
//   - retained: the candidate is still in its session, so the same sign-in
//     can be retried. That's every failure before the rename, and a rename
//     that fails while the candidate is still in place (for example a Windows
//     sharing violation because rclone has the old config open);
//   - activated: the rename succeeded, even if a later step fails;
//   - indeterminate: the rename failed and the candidate is gone or can't be
//     checked, so we can't tell where it ended up.
//
// After the rename, rclone's own leftover save files in the vault folder are
// removed (see removeRcloneConfigLeftovers).
func publishRcloneVaultConfig(staged, repositoryID string) (RcloneConfigActivation, error) {
	target, err := RcloneVaultConfigPath(repositoryID)
	result := retainedRcloneConfig(target)
	if err != nil {
		return result, err
	}
	if err := recognizedRcloneConfigSessionPath(filepath.Dir(staged)); err != nil ||
		filepath.Base(staged) != "rclone.conf" {
		return result, fmt.Errorf("rclone config candidate is outside the private config-session root")
	}
	if err := validateRcloneVaultFile(staged); err != nil {
		return result, fmt.Errorf("staged rclone config is unusable: %w", err)
	}
	directory := filepath.Dir(target)
	if err := makePrivateRcloneDirectory(directory); err != nil {
		return result, fmt.Errorf("prepare rclone config publication: %w", err)
	}
	if err := renameRcloneConfigCandidate(staged, target); err != nil {
		if _, statErr := os.Lstat(staged); statErr != nil {
			result.Disposition = RcloneConfigIndeterminate
		}
		return result, fmt.Errorf("activate rclone vault config: %w", err)
	}
	result.Disposition = RcloneConfigActivated
	if err := syncRcloneVaultPublicationDirectory(directory); err != nil {
		return result, fmt.Errorf("sync rclone vault directory: %w", err)
	}
	removeRcloneConfigLeftovers(directory)
	if err := validateRcloneVaultFile(target); err != nil {
		return result, err
	}
	return result, nil
}

// removeRcloneConfigLeftovers deletes rclone's own temporary save files from a
// vault folder, after a new config has been published there and when startup
// cleans up the folder of a vault that no longer exists. Rclone 1.75.1
// saves a config by writing os.CreateTemp(dir, "rclone.conf") (that is,
// rclone.conf<digits>), moving the old file to os.CreateTemp(dir,
// "rclone.conf.old") (rclone.conf.old<digits>), renaming the new file into
// place and deleting the old one. An interrupted save leaves one or both
// behind. They're ignored while the vault is in use, and cleared here so they
// don't pile up.
//
// Only those two name shapes are removed; anything else in the folder
// is left alone. Failures are ignored because the leftovers are harmless.
// Replicaro never tries to recover a token from these files: if a save was
// interrupted after rclone.conf was moved aside, the vault reports "reconnect
// required" and a new sign-in replaces it.
func removeRcloneConfigLeftovers(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if rcloneConfigLeftoverName(entry.Name()) {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
}

// rcloneConfigLeftoverName matches ^rclone\.conf[0-9]+$ and
// ^rclone\.conf\.old[0-9]+$.
func rcloneConfigLeftoverName(name string) bool {
	for _, prefix := range []string{"rclone.conf.old", "rclone.conf"} {
		digits, ok := strings.CutPrefix(name, prefix)
		if !ok || digits == "" {
			continue
		}
		allDigits := true
		for _, character := range digits {
			if character < '0' || character > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return true
		}
	}
	return false
}

// syncRcloneConfigDirectory flushes a rename in path to disk on Unix, so a
// crash right after publication can't bring back the old config. NTFS records
// the rename in its journal, and Windows can't flush a directory handle opened
// the normal way, so there's nothing to do there.
func syncRcloneConfigDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

// sweepRcloneSessions removes the op-*, auth-* and config-* folders left in the
// session roots by an earlier process that crashed or was killed. Anything
// else in those roots is left alone. Each folder goes with os.RemoveAll, which
// deletes links, FIFOs and hard links inside it as plain entries without
// following them, so whatever they point to is untouched.
//
// A folder that can't be removed is reported but doesn't stop the sweep, and
// the caller only logs it: a stale session can't affect a new one, which
// always gets a fresh random name. Don't make a failed removal stop startup;
// the same stale folder would then block every restart.
//
// This must only run once per process, before any rclone operation starts,
// because it removes every op-* folder (see ensureRcloneSessionsCleaned).
func sweepRcloneSessions() error {
	var result error
	for _, root := range []func() (string, error){
		appdata.RcloneSessionRoot,
		appdata.RcloneConfigSessionRoot,
	} {
		parent, err := root()
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		entries, err := os.ReadDir(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !validRcloneAuthorizationDirectoryName(name) &&
				!validRcloneOperationDirectoryName(name) &&
				!validRcloneConfigDirectoryName(name) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(parent, name)); err != nil {
				result = errors.Join(result, fmt.Errorf("remove stale rclone session: %w", err))
			}
		}
	}
	return result
}
