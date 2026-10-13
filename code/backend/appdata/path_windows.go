//go:build windows

package appdata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// localAppDataKnownFolder is a variable so tests can make the lookup fail.
var localAppDataKnownFolder = func() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
}

// File returns a durable per-user path. Existing files outside this directory
// are never inspected or migrated.
func File(name string) (string, error) {
	root, err := rootDirectory()
	if err != nil {
		return "", err
	}
	if err := ensureApplicationRoot(root); err != nil {
		return "", err
	}
	cleanName, err := safeRelativeName(name)
	if err != nil {
		return "", err
	}
	destination := filepath.Join(root, cleanName)
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("create application data directory: %w", err)
	}
	return destination, nil
}

func Directory(name string) (string, error) {
	root, err := rootDirectory()
	if err != nil {
		return "", err
	}
	if err := ensureApplicationRoot(root); err != nil {
		return "", err
	}
	cleanName, err := safeRelativeName(name)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, cleanName)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create application data directory: %w", err)
	}
	return directory, nil
}

// ensureApplicationRoot creates the application folder
// (%LOCALAPPDATA%\Replicaro) and gives it the protected DACL from SecurePath
// at that moment. Its entries are inheritable, so every folder and file
// created under it later carries the same user, LocalSystem and
// Administrators entries without an ACL write of its own. If a concurrent
// caller creates a child before the DACL lands, SetNamedSecurityInfo pushes
// the inherited entries down to it anyway.
//
// A root that already exists is used as it is, including one secured by an
// earlier version. Re-stamping it on every call would only matter if someone
// had changed its ACL since, and tampering by someone with access to the
// computer isn't something Replicaro defends against. It's also expensive:
// setting an inheritable DACL propagates through every existing child, Kopia
// caches included, and Directory runs several times per engine command.
// Don't add per-call ACL writes back here, or to the callers below the root,
// without a product decision.
//
// There are two ways a root ends up without the protected DACL: the process
// dies between Mkdir and SecurePath, or SecurePath fails after a concurrent
// first launch has already created a child, so the os.Remove below can't
// take the root away. Either way the root keeps the ACL it inherited from
// %LOCALAPPDATA%, which normally grants the same user, LocalSystem and
// Administrators entries, just not protected from later inheritance changes.
// That's an accepted gap. Don't add a per-call DACL check to recover from it:
// it brings back the per-call ACL cost described above for a rare case that
// is still owner-only in practice.
func ensureApplicationRoot(root string) error {
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		return fmt.Errorf("create application data root: %w", err)
	}
	err := os.Mkdir(root, 0o700)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create application data root: %w", err)
	}
	if err := SecurePath(root, true); err != nil {
		// Don't leave a root with the default inherited ACL behind: nothing
		// would secure it later. The next call creates it again.
		return errors.Join(err, os.Remove(root))
	}
	return nil
}

func safeRelativeName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	// filepath.IsAbs intentionally reports rooted drive-relative names such as
	// `\outside` as non-absolute on Windows. Joining one of those names still
	// discards the application-data tail, so reject every rooted spelling.
	if filepath.IsAbs(name) || filepath.IsLocal(name) == false {
		return "", fmt.Errorf("application data path must be relative")
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("application data path escapes the application root")
	}
	return clean, nil
}
