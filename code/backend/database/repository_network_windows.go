//go:build windows

package database

import (
	"strings"

	"github.com/local/replicaro/storageidentity"
	"golang.org/x/sys/windows"
)

// isNetworkFilesystemLocation picks the "Network" or "Local" label shown on a
// filesystem vault card. Windows keeps the UNC text check plus GetDriveType on
// the drive root: that call reads the local drive table and does not contact
// the server, so a disconnected mapped drive cannot hang it. Only
// \\server\share and \\?\UNC\ paths count as network by their text; an
// extended \\?\X:\ path is a drive path and gets the drive check like X:\.
// The recorded facts are not needed here because Windows network paths are
// recorded with no filesystem type at all (see storageidentity.observeFacts).
//
// Do not add a call that opens or queries the vault folder itself (volume
// information, final path names, and so on). ListRepositories runs this for
// every row while holding the single SQLite writer connection, so a hung SMB
// share would stall every database write in the process.
func isNetworkFilesystemLocation(connector, location string, _ storageidentity.Facts) bool {
	if !strings.EqualFold(strings.TrimSpace(connector), "fs") {
		return false
	}
	network, driveRoot := windowsLocationKind(location)
	if network || driveRoot == "" {
		return network
	}
	root, err := windows.UTF16PtrFromString(driveRoot)
	if err != nil {
		return false
	}
	return windows.GetDriveType(root) == windows.DRIVE_REMOTE
}
