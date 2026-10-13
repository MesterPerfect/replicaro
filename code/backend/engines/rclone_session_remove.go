package engines

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/local/replicaro/appdata"
)

func recognizedRcloneSessionPath(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	operationParent, err := appdata.RcloneSessionRoot()
	if err != nil {
		return "", "", err
	}
	operationParent, err = filepath.Abs(operationParent)
	if err != nil {
		return "", "", err
	}
	configParent, err := appdata.RcloneConfigSessionRoot()
	if err != nil {
		return "", "", err
	}
	configParent, err = filepath.Abs(configParent)
	if err != nil {
		return "", "", err
	}
	absolute = filepath.Clean(absolute)
	operationParent = filepath.Clean(operationParent)
	configParent = filepath.Clean(configParent)
	name := filepath.Base(absolute)
	parent := filepath.Dir(absolute)
	operationSession := parent == operationParent &&
		(validRcloneAuthorizationDirectoryName(name) || validRcloneOperationDirectoryName(name))
	configSession := parent == configParent && validRcloneConfigDirectoryName(name)
	if !operationSession && !configSession {
		return "", "", fmt.Errorf("rclone cleanup target is not a recognized private session")
	}
	return parent, name, nil
}

func recognizedRcloneConfigSessionPath(path string) error {
	parent, name, err := recognizedRcloneSessionPath(path)
	if err != nil {
		return err
	}
	configParent, err := appdata.RcloneConfigSessionRoot()
	if err != nil {
		return err
	}
	configParent, err = filepath.Abs(configParent)
	if err != nil {
		return err
	}
	if filepath.Clean(parent) != filepath.Clean(configParent) || !validRcloneConfigDirectoryName(name) {
		return fmt.Errorf("rclone config candidate is outside the private config-session root")
	}
	return nil
}

// removeRcloneSessionTree removes one recognized config, authorization or
// operation session folder with everything in it. The name check keeps the
// removal to an immediate op-*, auth-* or config-* child of a session root;
// os.RemoveAll then deletes links inside it (or a session name that is itself
// a link) without following them, so nothing outside the session is touched.
func removeRcloneSessionTree(root string) error {
	if _, _, err := recognizedRcloneSessionPath(root); err != nil {
		return err
	}
	return os.RemoveAll(root)
}
