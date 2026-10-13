package vaultprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/local/replicaro/engines"
)

// A password change keeps one small record next to its staged objects from
// just before the native password command first starts until the change is
// committed or rolled back. Recovery reads it to finish an interrupted native
// command without guessing:
//
//   - Reruns counts how many times recovery has started the native command
//     again. It is saved, atomically, before each rerun launches, so a crash
//     between saving and launching can only overcount, never let a fourth
//     rerun through.
//   - RollingBack is set, atomically, before rollback removes the first remote
//     fence. From then on recovery only continues the rollback, and it accepts
//     the half-unfenced vault that an interrupted rollback leaves behind.
//   - ResticKeyID is the Restic key the committed password opened just before
//     the first launch. Every `key passwd` is pointed at it with --key-hint,
//     and forward recovery removes that key, and no other, when an interrupted
//     `key passwd` added the new key but did not get to remove the old one.
//     Other keys, including another key with the same old password, are never
//     touched.
//   - Kopia is a copy of Kopia's two format blobs as they were just before the
//     first launch (see PasswordRotationKopiaFormat). It lets recovery undo
//     the one state an interrupted `repository change-password` leaves that
//     neither password opens. Every Kopia record has it: the change refuses
//     to start without a copy it can rely on.
//
// The record holds no password. It is replaced as a whole (temporary file,
// fsync, rename, folder fsync), so a crash leaves either the old or the new
// record, never a torn one. A record left behind after its database row is
// gone does nothing: recovery only starts from a row.
//
// New fields must be optional, with their zero value meaning "not recorded",
// so a record written by an earlier build still loads. Raise Version only if
// the meaning of an existing field changes.
type PasswordRotationRecord struct {
	Version       int                          `json:"version"`
	RepositoryID  string                       `json:"repositoryId"`
	OperationUUID string                       `json:"operationUUID"`
	Engine        string                       `json:"engine"`
	Reruns        int                          `json:"reruns"`
	RollingBack   bool                         `json:"rollingBack,omitempty"`
	ResticKeyID   string                       `json:"resticKeyId,omitempty"`
	Kopia         *PasswordRotationKopiaFormat `json:"kopia,omitempty"`
}

// PasswordRotationKopiaFormat is what a Kopia password change saves about the
// repository's format blobs before Kopia first runs `repository
// change-password`. Kopia rewrites kopia.blobcfg (encrypted with a key derived
// from the password) and then kopia.repository (which holds the format
// encrypted the same way). Killed between the two writes, the repository opens
// with neither password: the new kopia.blobcfg needs the new password, the old
// kopia.repository the old one.
//
// Recovery puts the saved kopia.blobcfg back only when kopia.repository still
// hashes to RepositorySHA256 and kopia.blobcfg no longer matches the saved
// bytes, which restores the pair the old password opens, and then runs the
// change again. The names are the object names at the vault root, as
// found before the launch by comparing the storage read with `kopia blob show`
// (measured: filesystem, SFTP and WebDAV add ".f"; S3 doesn't; any other
// backend's name is whichever spelling that comparison matches). Blobcfg holds
// Kopia's own bytes, already encrypted by Kopia; it is not a password.
type PasswordRotationKopiaFormat struct {
	RepositoryName   string `json:"repositoryName"`
	RepositorySHA256 string `json:"repositorySha256"`
	BlobcfgName      string `json:"blobcfgName"`
	BlobcfgSHA256    string `json:"blobcfgSha256"`
	Blobcfg          []byte `json:"blobcfg"`
}

const (
	PasswordRotationRecordVersion = 1

	passwordRotationRecordName     = "recovery.json"
	passwordRotationRecordTempName = "recovery.json.tmp"
	passwordRotationFenceName      = "native.lock"

	// The record is a few hundred bytes, or a few KiB with a Kopia format copy
	// (bounded by MaximumKopiaFormatBlobBytes); the bound only stops a damaged
	// file from being read whole.
	maximumPasswordRotationRecordBytes = 64 << 10
	// Far above the number of reruns recovery ever allows; anything larger
	// means the file is damaged.
	maximumPasswordRotationRecordReruns = 100
)

// ErrPasswordRotationRecordMissing reports that the change has no record. A
// change saved in native_started by a build that didn't write one, or whose
// stage folder is gone, gets this and keeps the older manual recovery.
var ErrPasswordRotationRecordMissing = errors.New("password-change recovery record is missing")

func validatePasswordRotationRecord(record PasswordRotationRecord) error {
	if record.Version != PasswordRotationRecordVersion || !exactUUID(record.RepositoryID) || !exactUUID(record.OperationUUID) ||
		record.Reruns < 0 || record.Reruns > maximumPasswordRotationRecordReruns {
		return fmt.Errorf("password-change recovery record is invalid")
	}
	switch record.Engine {
	case "restic":
		if !validResticKeyID(record.ResticKeyID) || record.Kopia != nil {
			return fmt.Errorf("password-change recovery record has an invalid Restic key")
		}
	case "kopia":
		if record.ResticKeyID != "" || record.Kopia == nil {
			return fmt.Errorf("password-change recovery record is invalid")
		}
		if err := validatePasswordRotationKopiaFormat(*record.Kopia); err != nil {
			return err
		}
	default:
		return fmt.Errorf("password-change recovery record is invalid")
	}
	return nil
}

// validatePasswordRotationKopiaFormat checks a saved Kopia format copy. The
// names are limited to the two spellings Kopia's backends use, so a damaged
// record can never point a write-back at any other object.
func validatePasswordRotationKopiaFormat(saved PasswordRotationKopiaFormat) error {
	blobcfgSum := sha256.Sum256(saved.Blobcfg)
	if !slices.Contains(KopiaFormatBlobNames(engines.KopiaRepositoryBlob), saved.RepositoryName) ||
		!slices.Contains(KopiaFormatBlobNames(engines.KopiaBlobcfgBlob), saved.BlobcfgName) ||
		!validSHA256Hex(saved.RepositorySHA256) || !validSHA256Hex(saved.BlobcfgSHA256) ||
		len(saved.Blobcfg) == 0 || len(saved.Blobcfg) > MaximumKopiaFormatBlobBytes ||
		hex.EncodeToString(blobcfgSum[:]) != saved.BlobcfgSHA256 {
		return fmt.Errorf("password-change recovery record has an invalid Kopia format copy")
	}
	return nil
}

func validSHA256Hex(value string) bool {
	return len(value) == 2*sha256.Size && validLowerHex(value)
}

// validResticKeyID accepts only the full key ID `key list --json` prints, so
// a stored ID can never match more than one key as a prefix would.
func validResticKeyID(value string) bool {
	return len(value) == 64 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	if value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// WritePasswordRotationRecord replaces the change's record in its existing
// stage folder.
func WritePasswordRotationRecord(record PasswordRotationRecord) error {
	if err := validatePasswordRotationRecord(record); err != nil {
		return err
	}
	path, err := validatePasswordRotationStage(record.RepositoryID, record.OperationUUID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp := filepath.Join(path, passwordRotationRecordTempName)
	if err := removePasswordRotationFile(temp); err != nil {
		return err
	}
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		return err
	}
	if err := passwordRotationFault("recovery_record_temp_durable"); err != nil {
		return err
	}
	if err := os.Rename(temp, filepath.Join(path, passwordRotationRecordName)); err != nil {
		return err
	}
	return syncPasswordRotationDirectory(path)
}

// LoadPasswordRotationRecord reads the change's record. It returns
// ErrPasswordRotationRecordMissing when the stage folder or the record isn't
// there; a leftover temporary file alone is a write that never completed.
func LoadPasswordRotationRecord(repositoryID, operationUUID string) (PasswordRotationRecord, error) {
	var record PasswordRotationRecord
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if errors.Is(err, os.ErrNotExist) {
		return record, ErrPasswordRotationRecordMissing
	}
	if err != nil {
		return record, err
	}
	data, err := readPasswordRotationFileBounded(filepath.Join(path, passwordRotationRecordName), maximumPasswordRotationRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return record, ErrPasswordRotationRecordMissing
	}
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return PasswordRotationRecord{}, fmt.Errorf("password-change recovery record is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PasswordRotationRecord{}, fmt.Errorf("password-change recovery record has trailing content")
	}
	if err := validatePasswordRotationRecord(record); err != nil {
		return PasswordRotationRecord{}, err
	}
	if record.RepositoryID != repositoryID || record.OperationUUID != operationUUID {
		return PasswordRotationRecord{}, fmt.Errorf("password-change recovery record belongs to another change")
	}
	return record, nil
}

// PasswordRotationFencePath is the native-process fence file of the change,
// in its existing stage folder. The native password command and every later
// rerun, Restic unlock and key removal inherit the fence, so recovery can
// tell from it whether a command started by an earlier Replicaro process is
// still running. On Windows the fence is held in memory and no file exists.
func PasswordRotationFencePath(repositoryID, operationUUID string) (string, error) {
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, passwordRotationFenceName), nil
}

// CleanupPasswordRotationStageKeepingRecord removes everything a change
// staged except its record, manifest last, and keeps the folder. Rollback
// uses it before it gives up the database row, so the record, which tells an
// interrupted rollback to keep going, is still there until the very end.
func CleanupPasswordRotationStageKeepingRecord(repositoryID, operationUUID string) error {
	return cleanupPasswordRotationStage(repositoryID, operationUUID, true)
}
