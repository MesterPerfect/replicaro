//go:build (linux || darwin) && (amd64 || arm64)

package engines

import (
	"embed"
	"path"

	"github.com/local/replicaro/appdata"
)

// Each Unix build includes exactly one target directory selected by the
// build-specific targetAssetPath constant.
var embeddedUnixBinaries embed.FS

func embeddedEngine(id string) (appdata.Executable, error) {
	expected, err := expectedEmbeddedHash(id, targetAssetPath)
	if err != nil {
		return appdata.Executable{}, err
	}
	return appdata.ExecutableFromFS(embeddedUnixBinaries, path.Join("assets", targetAssetPath, id), expected), nil
}
