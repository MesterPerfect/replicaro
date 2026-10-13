package appdata

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	rootMu                sync.RWMutex
	testRootPath          string
	scopedProcessRootPath string
	scopedProcessRootSet  bool
)

// SetRootForTests isolates every app-data category for a test. Production code
// never calls this function and never infers test mode from the working dir.
func SetRootForTests(root string) func() {
	if info, err := os.Lstat(root); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		_ = SecurePath(root, true)
	}
	rootMu.Lock()
	previous := testRootPath
	testRootPath = root
	rootMu.Unlock()
	return func() {
		rootMu.Lock()
		testRootPath = previous
		rootMu.Unlock()
	}
}

// BeginScopedProcessRoot isolates every app-data and cache category for the
// lifetime of a standalone process operation. The caller must supply an
// absolute, already-created private directory and invoke the returned restore
// function before removing it. Only one process scope may be active at a time.
func BeginScopedProcessRoot(root string) (func(), error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("scoped process root must be absolute")
	}
	clean := filepath.Clean(root)
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect scoped process root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("scoped process root must be a real directory")
	}
	if err := SecurePath(clean, true); err != nil {
		return nil, fmt.Errorf("protect scoped process root: %w", err)
	}

	rootMu.Lock()
	if testRootPath != "" || scopedProcessRootSet {
		rootMu.Unlock()
		return nil, fmt.Errorf("an app-data root override is already active")
	}
	scopedProcessRootSet = true
	scopedProcessRootPath = clean
	rootMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			rootMu.Lock()
			scopedProcessRootPath = ""
			scopedProcessRootSet = false
			rootMu.Unlock()
		})
	}, nil
}

func rootDirectory() (string, error) {
	rootMu.RLock()
	testRoot := testRootPath
	processRoot := scopedProcessRootPath
	rootMu.RUnlock()
	if testRoot != "" {
		return filepath.Abs(testRoot)
	}
	if processRoot != "" {
		return processRoot, nil
	}
	if runtime.GOOS == "windows" {
		localAppData, err := windowsLocalAppData()
		if err != nil {
			return "", err
		}
		return absoluteRoot(filepath.Join(localAppData, "Replicaro"))
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve user home for application data: %w", err)
	}
	if runtime.GOOS == "darwin" {
		return absoluteRoot(filepath.Join(home, "Library", "Application Support", "Replicaro"))
	}
	if value := xdgBaseDirectory("XDG_STATE_HOME"); value != "" {
		return absoluteRoot(filepath.Join(value, "replicaro"))
	}
	return absoluteRoot(filepath.Join(home, ".local", "state", "replicaro"))
}

// windowsLocalAppData returns the per-user Local AppData folder that holds
// Replicaro's data on Windows. LOCALAPPDATA normally names it and is used
// when it holds an absolute path, so a redirected profile keeps working.
// A launcher that builds a minimal environment can leave it out, though,
// while the folder itself still exists. Asking Windows for the known folder
// then finds the same place a normal launch uses, instead of refusing to
// start or resolving a relative value against the working directory.
func windowsLocalAppData() (string, error) {
	if value := os.Getenv("LOCALAPPDATA"); filepath.IsAbs(value) {
		return value, nil
	}
	value, err := localAppDataKnownFolder()
	if err != nil {
		return "", fmt.Errorf("LOCALAPPDATA is unset or relative, and the Local AppData known folder could not be found: %w", err)
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("LOCALAPPDATA is unset or relative, and the Local AppData known folder %q is not an absolute path", value)
	}
	return value, nil
}

// xdgBaseDirectory returns an XDG base-directory variable only when it holds
// an absolute path. The XDG Base Directory spec says relative values are
// invalid and should be ignored, so callers fall back to the default location
// instead of refusing to start (or quietly resolving against whatever the
// working directory happens to be).
func xdgBaseDirectory(name string) string {
	value := os.Getenv(name)
	if !filepath.IsAbs(value) {
		return ""
	}
	return value
}

// PasswordRotationRoot returns the one durable vault-password staging root
// without creating or permission-changing any component. The password-change
// code creates and cleans up its own stage under it.
func PasswordRotationRoot() (string, error) {
	root, err := rootDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "password-change"), nil
}

// OperationLogDirectoryPath returns the local diagnostic directory without
// creating or permission-changing it. The operation-log package creates it
// when it first writes a log.
func OperationLogDirectoryPath() (string, error) {
	root, err := rootDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "logs"), nil
}

// RcloneSessionRoot returns the private authorization/operation-session
// location without creating any path component. The rclone adapter creates
// this tree itself before it writes any credentials there.
func RcloneSessionRoot() (string, error) {
	root, err := rootDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "rclone", "sessions"), nil
}

// RcloneConfigSessionRoot returns the exact ephemeral native-config candidate
// root without creating it. It deliberately shares the durable configuration
// filesystem used by the canonical vault rclone configs; native
// cache, temporary, and other operation state remain under RcloneSessionRoot.
func RcloneConfigSessionRoot() (string, error) {
	rootMu.RLock()
	testRoot := testRootPath
	processRoot := scopedProcessRootPath
	rootMu.RUnlock()
	if testRoot != "" {
		root, err := filepath.Abs(testRoot)
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "config-sessions"), nil
	}
	if processRoot != "" {
		return filepath.Join(processRoot, "rclone", "config-sessions"), nil
	}
	if runtime.GOOS == "windows" {
		localAppData, err := windowsLocalAppData()
		if err != nil {
			return "", err
		}
		root, err := absoluteRoot(filepath.Join(localAppData, "Replicaro"))
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "config-sessions"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve user home for rclone configuration: %w", err)
	}
	if runtime.GOOS == "darwin" {
		root, err := absoluteRoot(filepath.Join(home, "Library", "Application Support", "Replicaro"))
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "config-sessions"), nil
	}
	configHome := xdgBaseDirectory("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	root, err := absoluteRoot(filepath.Join(configHome, "replicaro"))
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "rclone", "config-sessions"), nil
}

// RcloneVaultConfigRoot returns the exact durable per-vault native rclone
// configuration root without creating it.
func RcloneVaultConfigRoot() (string, error) {
	rootMu.RLock()
	testRoot := testRootPath
	processRoot := scopedProcessRootPath
	rootMu.RUnlock()
	if testRoot != "" {
		root, err := filepath.Abs(testRoot)
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "vaults"), nil
	}
	if processRoot != "" {
		return filepath.Join(processRoot, "rclone", "vaults"), nil
	}
	if runtime.GOOS == "windows" {
		localAppData, err := windowsLocalAppData()
		if err != nil {
			return "", err
		}
		root, err := absoluteRoot(filepath.Join(localAppData, "Replicaro"))
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "vaults"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve user home for rclone configuration: %w", err)
	}
	if runtime.GOOS == "darwin" {
		root, err := absoluteRoot(filepath.Join(home, "Library", "Application Support", "Replicaro"))
		if err != nil {
			return "", err
		}
		return filepath.Join(root, "rclone", "vaults"), nil
	}
	configHome := xdgBaseDirectory("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	root, err := absoluteRoot(filepath.Join(configHome, "replicaro"))
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "rclone", "vaults"), nil
}

// CacheDirectory returns disposable per-user cache/log storage. macOS keeps
// this outside Application Support so cache eviction cannot remove durable
// configuration or credentials.
func CacheDirectory(name string) (string, error) {
	rootMu.RLock()
	testRoot := testRootPath
	processRoot := scopedProcessRootPath
	rootMu.RUnlock()
	if testRoot != "" || processRoot != "" {
		return Directory(filepath.Join("cache", name))
	}
	if runtime.GOOS != "darwin" {
		return Directory(filepath.Join("cache", name))
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve user home for cache: %w", err)
	}
	root, err := absoluteRoot(filepath.Join(home, "Library", "Caches", "Replicaro"))
	if err != nil {
		return "", err
	}
	if err := ensureDirectory(root); err != nil {
		return "", err
	}
	clean, err := safeRelativeName(name)
	if err != nil {
		return "", err
	}
	directory := filepath.Join(root, clean)
	if err := ensureDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func absoluteRoot(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve application data path: %w", err)
	}
	return absolute, nil
}

func ensureDirectory(path string) error {
	return secureEnsureDirectory(path)
}
