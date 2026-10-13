// Package rclone materializes Replicaro's pinned rclone sidecar.
package rclone

import (
	"fmt"
	"path/filepath"

	"github.com/local/replicaro/appdata"
)

const (
	Version = "1.75.1"
)

var (
	BinarySHA256 = embeddedBinarySHA256()
	binaryName   = embeddedBinaryName()
)

// Materialize verifies and installs the embedded rclone executable in
// Replicaro's per-user application-data directory. The install and its
// checksum check happen the first time a run needs rclone; later calls only
// check that the installed file is still there with the same size and mode,
// and a failed install is tried again on the next call (see
// appdata.EnsureExecutable).
func Materialize() (string, error) {
	source, err := embeddedExecutable()
	if err != nil {
		return "", err
	}
	directory, err := appdata.Directory(filepath.Join("components", "rclone"))
	if err != nil {
		return "", fmt.Errorf("prepare rclone component directory: %w", err)
	}
	path, err := appdata.EnsureExecutable(source, directory, binaryName)
	if err != nil {
		return "", fmt.Errorf("install embedded rclone: %w", err)
	}
	return path, nil
}
