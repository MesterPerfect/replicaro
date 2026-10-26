package engines

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/local/replicaro/appdata"
)

func detectBinary(id, custom, name string) (string, string) {
	if custom != "" {
		if info, err := os.Stat(custom); err == nil && !info.IsDir() {
			return custom, ""
		}
		return "", "custom path does not exist or is not a file"
	}
	if path, err := extractBinary(id, name); err == nil {
		return path, ""
	}
	return "", "included binary could not be installed"
}

func extractBinary(id, name string) (string, error) {
	return extractEmbeddedBinary(id, name)
}

// extractEmbeddedBinary returns the path of the bundled engine, installing it
// under engines/<id>/ in the application folder. Every engine command
// resolves the engine again, so this goes through appdata.EnsureExecutable:
// the bundled bytes are hashed and installed once per run, and later calls
// only check that the installed file is still a regular file of the right
// size and mode.
func extractEmbeddedBinary(id, name string) (string, error) {
	source, err := embeddedEngine(id)
	if err != nil {
		return "", err
	}
	directory, err := appdata.Directory(filepath.Join("engines", id))
	if err != nil {
		return "", err
	}
	path, err := appdata.EnsureExecutable(source, directory, name)
	if err != nil {
		return "", fmt.Errorf("install embedded %s for %s/%s: %w", id, runtime.GOOS, runtime.GOARCH, err)
	}
	return path, nil
}
