//go:build !windows

package database

import (
	"context"
	"os"
)

// Both cache files have already been closed and synchronized on the same
// filesystem. Rename either preserves the original or publishes the replacement.
func replaceMetadataCacheFile(_ context.Context, source, destination string) error {
	return os.Rename(source, destination)
}
