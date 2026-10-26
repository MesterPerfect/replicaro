//go:build !windows

package appdata

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// atomicReplace renames a finished private file over its destination and
// fsyncs the folder so the new name survives a crash. Callers create the
// source in the destination's folder, usually with os.CreateTemp and
// sometimes under a fixed staging name (Kopia reconnect's .staged and
// .restore files), so the rename stays on one filesystem.
//
// There's intentionally no ancestor walk or symlink check on the source or
// destination here. rename(2) replaces a link at the destination rather than
// writing through it, and the remaining cases only matter if anyone with
// access to the computer (other local users or software running on it) is
// swapping files under us, which Replicaro doesn't try to defend against.
func atomicReplace(source, destination string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if mode != 0o600 && mode != 0o700 {
		mode = 0o600
	}
	if err := os.Chmod(source, mode); err != nil {
		return err
	}
	if sourceStat, ok := info.Sys().(*syscall.Stat_t); ok {
		if directoryInfo, statErr := os.Stat(filepath.Dir(destination)); statErr == nil {
			if destinationStat, ok := directoryInfo.Sys().(*syscall.Stat_t); ok && sourceStat.Dev != destinationStat.Dev {
				return fmt.Errorf("atomic replacement crosses filesystems")
			}
		}
	}
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, mode); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
