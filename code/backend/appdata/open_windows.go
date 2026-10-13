//go:build windows

package appdata

import (
	"os"

	"golang.org/x/sys/windows"
)

// OpenFileShareDelete is os.OpenFile, except that the handle also allows
// FILE_SHARE_DELETE. Go's own Windows open shares only reading and writing,
// so while one of its handles is open nobody can delete or rename the file:
// os.Remove fails with a sharing violation. Operation logs, captured command
// output and the rendezvous record are read while other code may remove them
// (log pruning, a finished command's cleanup, the running instance withdrawing
// its record), so their opens go through here.
//
// Only the access mode, O_CREATE and O_APPEND are supported, which is all its
// callers need; any other flag is rejected rather than ignored. O_EXCL is left
// out on purpose: matching Go's exclusive create would also need
// FILE_FLAG_OPEN_REPARSE_POINT so it doesn't follow a link at the name, and
// nothing here creates files exclusively. The other platforms reject the same
// flags so callers behave the same everywhere. Like
// os.OpenFile, the handle isn't inherited by child processes, and O_APPEND
// opens without FILE_WRITE_DATA so every write lands at the end of the file.
func OpenFileShareDelete(name string, flag int, perm os.FileMode) (*os.File, error) {
	const accessModes = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
	if flag&^(accessModes|os.O_CREATE|os.O_APPEND) != 0 {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrInvalid}
	}
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	var access uint32 = windows.GENERIC_READ
	switch flag & accessModes {
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA |
			windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if flag&os.O_CREATE != 0 {
		disposition = windows.OPEN_ALWAYS
	}
	attributes := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		attributes = windows.FILE_ATTRIBUTE_READONLY
	}
	handle, err := windows.CreateFile(path, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, disposition, attributes, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(handle), name), nil
}
