// Package rendezvous publishes where the running Replicaro serves its web
// interface, so a second launch can open it instead of starting another
// service.
//
// The instance guard decides which process owns the service. The owner writes
// a small record (replicaro.runtime.json in the app-data folder) once its
// listener is accepting connections and removes it at shutdown. A launch that
// loses the guard reads the URL from that record and opens it in the browser
// itself, then exits.
//
// The record is owner-only (0600 on Unix; on Windows it inherits the app-data
// folder's protected DACL), atomically replaced, size-bounded and strictly
// decoded, and it is only used while the PID it names is alive. Those checks
// cover crashes, half-written files and a stale record left by an old
// process. Nothing here tries to stop another program running as the same
// user from reading or rewriting the record: anything with that access can
// already drive Replicaro directly, and Replicaro doesn't defend against
// software or people that have access to the computer. Web pages are a
// different matter, and the API keeps them out with its Host, Origin,
// Fetch-Metadata, JSON and installation-UUID checks, none of which depend on
// this record.
//
// Don't add an activation endpoint, token check or ACL/owner verifier back
// here without a product decision: a second launch already has everything it
// needs to open the UI, and those checks only resisted local tampering.
package rendezvous

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/local/replicaro/appdata"
	"github.com/local/replicaro/runtimeendpoint"
)

const (
	RecordVersion  = "replicaro-rendezvous-v1"
	FileName       = "replicaro.runtime.json"
	maxRecordBytes = 4096
	retryInterval  = 25 * time.Millisecond
)

// Record is the published file. Replicaro reads only the PID and URL, and it
// accepts a record with or without the nonce and activation token.
//
// It still writes both as random values because other Replicaro versions
// require them when they read the record. A version that requires them treats
// a record without them as invalid: its second launch keeps waiting for a
// running instance until it gives up, and some versions also refuse to start
// over a leftover record they can't read. Don't stop writing them without a
// product decision about those versions.
type Record struct {
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
	PID     int    `json:"pid"`
	URL     string `json:"url"`
	Token   string `json:"activationToken"`
}

func NewRecord(endpoint runtimeendpoint.Endpoint) (Record, error) {
	nonce, err := randomSecret()
	if err != nil {
		return Record{}, err
	}
	token, err := randomSecret()
	if err != nil {
		return Record{}, err
	}
	record := Record{
		Version: RecordVersion, Nonce: nonce, PID: os.Getpid(),
		URL: endpoint.String(), Token: token,
	}
	return record, record.validate()
}

// PrepareOwner runs right after this process wins the instance guard, so no
// running Replicaro owns the record at path. Anything still there was left by
// an earlier owner that didn't shut down cleanly, and it's removed before the
// new record is published.
//
// That includes a record that can't be read or decoded: a leftover from a
// crash, from a run under sudo, or from an older or newer record format.
// Refusing to start over it would block every launch until someone found and
// deleted a hidden file by hand. When that happens the read error comes back
// as discarded so the caller can log it. A link whose target is gone counts
// too: opening follows the link and reports the record as missing, but
// Publish refuses anything at path, so leaving the link would fail every
// launch. path is always the fixed record name in the app-data folder, and
// os.Remove neither follows a link nor recurses into a folder, so nothing else
// can go with it. Startup only stops when the removal itself fails.
func PrepareOwner(path string) (discarded error, err error) {
	_, readErr := read(path, false)
	if errors.Is(readErr, os.ErrNotExist) {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return nil, nil
		}
		readErr = fmt.Errorf("link target is missing: %w", withoutPath(path, readErr))
	}
	if readErr == nil {
		return nil, Remove(path)
	}
	readErr = withoutPath(path, readErr)
	if removeErr := Remove(path); removeErr != nil {
		return nil, fmt.Errorf("Replicaro can't remove the leftover file %s (%w); it also couldn't be read (%w). Delete it and start Replicaro again",
			path, withoutPath(path, removeErr), readErr)
	}
	return readErr, nil
}

// withoutPath drops the *fs.PathError wrapper when it names path. The
// messages built from these errors already show path once, and the wrapped
// cause (permission denied, a decode error) is the part worth reading.
func withoutPath(path string, err error) error {
	if pathErr, ok := err.(*fs.PathError); ok && pathErr.Path == path {
		return pathErr.Err
	}
	return err
}

// Publish writes the record to a private temporary file in the same folder
// and renames it into place, so a reader never sees a partial record.
func Publish(path string, record Record) error {
	if err := record.validate(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("rendezvous destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".replicaro-runtime-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	// CreateTemp already uses 0600 on Unix. The explicit chmod keeps that
	// true whatever the umask or a future CreateTemp does; on Windows it's a
	// no-op and the file inherits the app-data folder's DACL.
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := appdata.AtomicReplace(temporary, path); err != nil {
		return err
	}
	keep = true
	return nil
}

// Remove deletes the record at path and ignores one that's already gone. The
// owner calls it at shutdown, and PrepareOwner uses it for a leftover from an
// earlier owner; both run while the instance guard is held.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ReadRunning returns the record only when it decodes cleanly and the process
// it names is still alive.
func ReadRunning(path string) (Record, error) {
	return read(path, true)
}

// WaitForRunningURL is what a launch that lost the instance guard uses. The
// owner takes the guard well before it publishes (it opens the database and
// runs startup recovery first), so a missing, stale or not-yet-valid record is
// retried until wait runs out.
func WaitForRunningURL(path string, wait time.Duration) (string, error) {
	deadline := time.Now().Add(wait)
	for {
		record, err := ReadRunning(path)
		if err == nil {
			return record.URL, nil
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("find the running Replicaro: %w", err)
		}
		time.Sleep(min(retryInterval, time.Until(deadline)))
	}
}

func read(path string, requireLivePID bool) (Record, error) {
	// A second launch polls this file while the owner may be removing it
	// (stale-record cleanup at startup, or shutdown). A plain os.Open on
	// Windows doesn't share delete, so the owner's os.Remove would fail with
	// a sharing violation for as long as a reader held it open.
	file, err := appdata.OpenFileShareDelete(path, os.O_RDONLY, 0)
	if err != nil {
		return Record{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return Record{}, err
	}
	if len(data) > maxRecordBytes {
		return Record{}, fmt.Errorf("rendezvous record exceeds limit")
	}
	var record Record
	if err := decodeStrict(data, &record); err != nil {
		return Record{}, fmt.Errorf("decode rendezvous record: %w", err)
	}
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	if requireLivePID && !processAlive(record.PID) {
		return Record{}, fmt.Errorf("rendezvous process is not active")
	}
	return record, nil
}

func (record Record) validate() error {
	if record.Version != RecordVersion || record.PID <= 0 {
		return fmt.Errorf("rendezvous record fields are invalid")
	}
	endpoint, err := runtimeendpoint.ParseExact(record.URL)
	if err != nil || endpoint.String() != record.URL {
		return fmt.Errorf("rendezvous URL is invalid")
	}
	return nil
}

func randomSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate rendezvous secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}
