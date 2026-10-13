//go:build windows && amd64

package engines

import (
	"embed"

	"github.com/local/replicaro/appdata"
)

//go:embed assets/restic.exe assets/kopia.exe
var embeddedBinaries embed.FS

func embeddedEngine(id string) (appdata.Executable, error) {
	expected, err := expectedEmbeddedHash(id, "windows_amd64")
	if err != nil {
		return appdata.Executable{}, err
	}
	return appdata.ExecutableFromFS(embeddedBinaries, "assets/"+id+".exe", expected), nil
}
