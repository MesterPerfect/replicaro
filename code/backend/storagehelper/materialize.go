// Package storagehelper materializes and launches Replicaro's target-native,
// embedded filesystem storage helper.
package storagehelper

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/local/replicaro/appdata"
)

const componentDirectory = "storage-helper"

var materializeMu sync.Mutex

// Materialize verifies and, when necessary, atomically recreates the embedded
// storage helper in Replicaro's private per-user application-data directory.
func Materialize() (string, error) {
	binary, expected, err := embeddedComponent()
	if err != nil {
		return "", componentError(err)
	}
	root, err := appdata.Directory("")
	if err != nil {
		return "", componentError(fmt.Errorf("resolve application-data root: %w", err))
	}
	return materializeBinary(binary, expected, root, executableName())
}

// materializeBinary installs the helper at
// root/components/storage-helper/<name> with appdata.InstallExecutable,
// creating the component folders first. A regular file with the embedded
// checksum is kept and set back to 0700; anything else at the path, a file
// whose mode can't be reset included, is replaced (see InstallExecutable).
// If the entry can't be replaced (a folder at that name, or a folder we can't
// write to), the ordinary filesystem error comes back and the helper stays
// unavailable.
//
// What heals on its own and what doesn't: an unreadable, mismatched, or
// root-owned helper file inside folders the user owns is simply reinstalled,
// because the rename only needs write access to the folder. Running Replicaro
// once under sudo can also leave components/ or components/storage-helper/
// root-owned with mode 0700, and those can't even be entered, so the helper
// stays unavailable until the user chowns them back. That's the same
// trade-off appdata accepts for its own folders (see the sudo note on
// secureEnsureDirectory in appdata/security_other.go).
//
// There are intentionally no owner, link, or letter-case checks on the
// folders or the binary, and no sudo detection. Those only matter against
// someone with access to the computer tampering with Replicaro's files, which
// Replicaro doesn't defend against, and they turned ordinary setups
// (symlinked home folders, case-variant siblings) into a disabled helper.
// Don't add owner or link checks back here without a product decision.
func materializeBinary(binary []byte, expected, root, name string) (string, error) {
	materializeMu.Lock()
	defer materializeMu.Unlock()

	// New folders get 0700 on Unix. On Windows they inherit the application
	// folder's protected DACL; this runs on every full preparation, so it
	// doesn't re-apply an ACL or mode to folders that already exist.
	directory := filepath.Join(root, "components", componentDirectory)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", componentError(fmt.Errorf("prepare component directory: %w", err))
	}
	path, err := appdata.InstallExecutable(appdata.ExecutableFromBytes(binary, expected), directory, name)
	if err != nil {
		return "", componentError(err)
	}
	return path, nil
}

func componentError(err error) error {
	return fmt.Errorf("storage helper component unavailable: %w", err)
}
