//go:build !windows

package appdata

import "os"

// OpenFileShareDelete is os.OpenFile. Unix already lets other code delete or
// rename a file that is open; the Windows version adds FILE_SHARE_DELETE to
// get the same behavior there.
//
// It accepts the same flags as the Windows version (the access mode, O_CREATE
// and O_APPEND) and rejects anything else, so a caller that only runs its
// tests on Unix can't come to depend on a flag Windows refuses.
func OpenFileShareDelete(name string, flag int, perm os.FileMode) (*os.File, error) {
	const accessModes = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
	if flag&^(accessModes|os.O_CREATE|os.O_APPEND) != 0 {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrInvalid}
	}
	return os.OpenFile(name, flag, perm)
}
