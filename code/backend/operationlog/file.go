package operationlog

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/local/replicaro/appdata"
)

// Operation logs are plain files in the logs folder under the app-data root.
// Native output is staged in the command-output folder, where the command
// runner captured it, and appended from there (see StageNativeOutput). Both
// folders come from appdata.Directory and are created owner-only (0700, or on
// Windows they inherit the application folder's protected DACL), new files
// are created 0600 and inherit the same DACL, and the main log is opened
// O_APPEND so every section lands at the end.
//
// There's deliberately no handle-relative open, no link, link-count or owner
// check, and no per-call ACL write. Those only resist someone with access to
// the computer swapping or hard-linking files in Replicaro's own folder,
// which Replicaro doesn't defend against, and the Windows link-count refusal
// made a log that had picked up a second link impossible to prune. Don't add
// them back without a product decision.
//
// Opens go through appdata.OpenFileShareDelete so that, on Windows as on
// Unix, a log can be removed while someone is still reading it (support
// reports sample logs without the per-operation lock), and a staged capture
// file can be appended and deleted even if an engine adapter still holds a
// reader on it.

func operationLogDirectory() (string, error) {
	return appdata.Directory("logs")
}

// openAppend opens the operation log for appending, creating it 0600. On Unix
// it also sets 0600 on a log that already exists: a restore or copy that
// didn't keep modes can leave an older log group- or world-readable, and the
// next append puts it back to owner-only. Windows is skipped because Chmod
// there only toggles the read-only attribute, so it would clear a read-only
// flag the user set instead of tightening anything.
func openAppend(path string) (*os.File, error) {
	file, err := appdata.OpenFileShareDelete(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	return file, nil
}

func openRead(path string) (*os.File, error) {
	return appdata.OpenFileShareDelete(path, os.O_RDONLY, 0)
}

// removeOperationLogFile deletes one log or stage file. On Windows os.Remove
// clears the read-only attribute and retries, which would delete a log the
// user marked read-only. Such a file is reported as a permission error and
// left in place instead.
func removeOperationLogFile(path string) error {
	if runtime.GOOS == "windows" {
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o200 == 0 {
			return &os.PathError{Op: "remove", Path: path, Err: os.ErrPermission}
		}
	}
	return os.Remove(path)
}

func cleanupStagedOutputFiles(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, entry := range entries {
		if !stageFilename(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		if removeErr := removeOperationLogFile(filepath.Join(directory, entry.Name())); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			cleanupErrors = append(cleanupErrors, removeErr)
		}
	}
	return errors.Join(cleanupErrors...)
}
