package database

import (
	"strings"

	"github.com/local/replicaro/storageidentity"
)

func isUNCFilesystemLocation(location string) bool {
	normalized := strings.TrimSpace(strings.ReplaceAll(location, "/", "\\"))
	return strings.HasPrefix(normalized, "\\\\")
}

// windowsLocationKind reads a Windows filesystem location as text only. It
// reports network for \\server\share and \\?\UNC\server\share. Otherwise it
// returns the drive root of X:\ or its \\?\X:\ spelling ("" when there is
// none), and the caller asks the drive table about that drive, so a mapped
// network drive is still network while \\?\C:\ is the local C: drive.
//
// It has no build tag so its tests run on every platform; only the Windows
// label uses it.
func windowsLocationKind(location string) (network bool, driveRoot string) {
	location = strings.TrimSpace(location)
	if _, ok := storageidentity.WindowsNetworkMountFromText(location); ok {
		return true, ""
	}
	driveRoot, _ = storageidentity.WindowsDriveFromText(location)
	return false, driveRoot
}
