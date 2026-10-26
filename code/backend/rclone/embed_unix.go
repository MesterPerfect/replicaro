//go:build (linux || darwin) && (amd64 || arm64)

package rclone

import (
	"embed"

	"github.com/local/replicaro/appdata"
)

var embeddedUnixAssets embed.FS

func embeddedExecutable() (appdata.Executable, error) {
	return appdata.ExecutableFromFS(embeddedUnixAssets, "assets/"+embeddedTarget+"/rclone", BinarySHA256), nil
}
func embeddedBinaryName() string { return "rclone" }
