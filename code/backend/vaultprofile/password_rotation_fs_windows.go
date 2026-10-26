//go:build windows

package vaultprofile

func syncPasswordRotationDirectory(string) error {
	// Windows has no supported directory fsync: FlushFileBuffers on a directory
	// fails with ERROR_ACCESS_DENIED, which does not indicate data loss. Every
	// staged file is flushed before its directory is published, so there is
	// nothing left to do here.
	return nil
}
