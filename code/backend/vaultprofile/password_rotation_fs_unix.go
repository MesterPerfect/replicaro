//go:build !windows

package vaultprofile

import "os"

func syncPasswordRotationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errorsJoin(directory.Sync(), directory.Close())
}

func errorsJoin(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
