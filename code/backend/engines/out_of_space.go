package engines

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/models"
)

// OutOfSpaceNoteKey is the catalog key of the one out-of-space note. The
// note is presentation only: it is added after a failure the engine or rclone
// already reported, and it never changes a status, a retry, a schedule or a
// native command.
//
// Where it is shown:
//   - a failed backup's result text, in English (it sits in the log with the
//     native output, and nothing in a log is translated);
//   - the vault card's saved profile-sync error, in the saved UI language at
//     the time the error is saved;
//   - the Activity entry (English, after the vault's name) a Kopia policy
//     that stays out of space for 6 hours writes instead of the reconnect
//     issue. Its notification uses a message of its own that names the vault
//     (vaultreconnect.OutOfSpaceMessageKey).
const OutOfSpaceNoteKey = "notifications.message.vaultOutOfSpace"

// storageFullMarkers is the one list of native out-of-space wording, by vault
// connector. The backup note, the profile-sync classifier in package command
// (it gets the list through command.ContextWithStorageFullMarkers) and the
// Kopia policy check all read it here; don't keep a second copy anywhere.
//
// Only these connectors get a note. SFTP, WebDAV (which also has a 507),
// S3-compatible, B2, Azure, GCS and Any Rclone Remote vaults are left out on
// purpose even when similar text shows up: the wording there comes from
// servers and providers we can't pin, and a wrong "out of space" is worse
// than none. Markers are matched case-insensitively and only after the
// vault's own path (and the job's source paths, for backups and Kopia policy
// updates) is taken out of the text, so a folder named after a marker can't
// trigger the note.
//
// Upkeep: every rclone, Restic or Kopia version bump needs these rechecked
// against the new binaries' wording (run a backup and a profile upload to a
// small full filesystem; the cloud ones come from rclone's backends and
// provider error codes). A marker that silently stops matching just drops the
// note, so nothing else catches it.
var storageFullMarkers = map[string][]string{
	// Local, USB, mounted and mapped-drive vaults. The Linux/macOS errno
	// texts, the three Windows errors Go reports in English (112 disk full,
	// 39 handle disk full, 1295 quota), and rclone's local backend, which
	// says "preallocate: file too big for remaining disk space" instead of
	// "no space left" when it uploads the recovery profile.
	"fs": {
		"no space left on device",
		"disk quota exceeded",
		"there is not enough space on the disk.",
		"the disk is full.",
		"the requested operation cannot be completed due to a disk quota violation.",
		"preallocate: file too big for remaining disk space",
	},
	// Google appends the reason code to "googleapi: Error 403: ...".
	"google_drive": {"storagequotaexceeded"},
	// rclone's Dropbox backend checks for this exact error tag itself.
	"dropbox":  {"insufficient_space"},
	"onedrive": {"quotalimitreached", "507 insufficient storage"},
}

// StorageFullMarkers returns the lowercased out-of-space markers for a vault
// connector, or nil when the connector gets no note.
func StorageFullMarkers(connector string) []string {
	connector = strings.TrimSpace(connector)
	if connector == "" {
		connector = "fs"
	}
	return append([]string(nil), storageFullMarkers[connector]...)
}

// storageFullRemovals lists the spellings of the vault's path (and any extra
// paths, such as the job's source) that are taken out of native text before
// the markers are matched. Every spelling keeps a path separator, so a short
// bare name is never cut out of the middle of rclone's or an engine's own
// words.
func storageFullRemovals(repo models.Repository, extra ...string) []string {
	location := strings.TrimSpace(repo.Location)
	candidates := []string{repo.Location, location}
	if repo.Connector == "" || repo.Connector == "fs" {
		clean := filepath.Clean(location)
		candidates = append(candidates, clean, filepath.ToSlash(clean), strings.TrimLeft(clean, `/\`))
	}
	for _, value := range extra {
		if value = strings.TrimSpace(value); value != "" {
			clean := filepath.Clean(value)
			candidates = append(candidates, value, clean, filepath.ToSlash(clean))
		}
	}
	values := make([]string, 0, 2*len(candidates))
	for _, value := range candidates {
		if strings.ContainsAny(value, `/\`) {
			// Our own Kopia policy error wrappers print targets with %q,
			// which doubles every backslash in a Windows path (and escapes
			// anything unprintable), so the Go-quoted spelling without its
			// surrounding quotes is taken out too.
			quoted := strconv.Quote(value)
			values = append(values, strings.ToLower(value), strings.ToLower(quoted[1:len(quoted)-1]))
		}
	}
	// Longest first, so a shorter spelling can't split a longer one.
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

// textHasStorageFullMarker lowercases one line of native text, replaces each
// removal with NUL (no marker contains NUL, so the replacement can't join two
// halves into a marker) and reports whether a marker is left.
func textHasStorageFullMarker(text string, markers, removals []string) bool {
	if len(markers) == 0 {
		return false
	}
	lower := strings.ToLower(text)
	for _, value := range removals {
		lower = strings.ReplaceAll(lower, value, "\x00")
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

type storageFullReportKey struct{}

// ContextWithStorageFullReport asks the backup started with the returned
// context to look for out-of-space wording if it fails. The returned function
// reports whether it found any. Only the backup runner asks: restores,
// checks and the rest never get the note (a full restore destination is not
// the vault's fault).
func ContextWithStorageFullReport(ctx context.Context) (context.Context, func() bool) {
	found := &atomic.Bool{}
	return context.WithValue(ctx, storageFullReportKey{}, found), found.Load
}

// reportBackupStorageFull reads a failed backup's captured output for the
// vault connector's markers and records a match for the runner. It reads:
//   - every stderr line, except Restic's per-file JSON "error" records and
//     Kopia's "Error when processing" / "Ignored error when processing" lines,
//     which quote source file names that could contain marker text; Restic's
//     JSON "exit_error" record is read by its message only;
//   - for Restic, the JSON "exit_error" records on stdout (stdout is
//     otherwise progress and summary records that list source files).
//
// The vault path and the source paths are taken out first. This is a reader
// for presentation only; it never changes the result.
func reportBackupStorageFull(ctx context.Context, repo models.Repository, capture *command.CapturedOutput, sources ...string) {
	found, _ := ctx.Value(storageFullReportKey{}).(*atomic.Bool)
	if found == nil || capture == nil {
		return
	}
	markers := StorageFullMarkers(repo.Connector)
	if len(markers) == 0 {
		return
	}
	removals := storageFullRemovals(repo, sources...)
	check := func(open func() (io.ReadCloser, error), stdout bool) bool {
		reader, err := open()
		if err != nil {
			return false
		}
		defer reader.Close()
		return scanStorageFullLines(reader, repo.Engine, stdout, func(text string) bool {
			return textHasStorageFullMarker(text, markers, removals)
		})
	}
	openStderr := func() (io.ReadCloser, error) { return capture.OpenStderr() }
	openStdout := func() (io.ReadCloser, error) { return capture.OpenStdout() }
	if check(openStderr, false) || (repo.Engine == ResticID && check(openStdout, true)) {
		found.Store(true)
	}
}

// scanStorageFullLines feeds the eligible lines of one stream to match and
// stops at the first match. A line longer than 1 MiB ends the scan; the note
// is a hint, so a partial read just means no note.
func scanStorageFullLines(reader io.Reader, engine string, stdout bool, match func(string) bool) bool {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if engine == ResticID && strings.HasPrefix(line, "{") {
			var record struct {
				MessageType string `json:"message_type"`
				Message     string `json:"message"`
			}
			if json.Unmarshal([]byte(line), &record) != nil || record.MessageType != "exit_error" {
				// Per-file "error" records, status and summary records.
				continue
			}
			if match(record.Message) {
				return true
			}
			continue
		}
		if stdout {
			continue
		}
		if engine == KopiaID && strings.Contains(line, `rror when processing "`) {
			continue
		}
		if match(line) {
			return true
		}
	}
	return false
}

// BackupPreparationStorageFull reports whether a backup whose requested
// native backup never started failed in one of the engine's own preparation
// commands with out-of-space wording. On a vault that is completely full,
// Restic can't even write the lock file of the repository check that runs
// before every backup, so on such a vault this is where the error usually
// shows up. Replicaro's own pre-native failures (a missing source, a paused
// vault, a refused writer check) carry no native command output and never
// match. The command's diagnostic text is read with the same line rules as a
// backup's stderr; preparation commands don't read the source, so it holds no
// source file names.
func BackupPreparationStorageFull(repo models.Repository, err error) bool {
	status, _, preparationErr, _, _, known := RequestedOperationOutcome(err)
	if !known || status != RequestedOperationNotStarted || preparationErr == nil {
		return false
	}
	var native *command.Error
	if !errors.As(preparationErr, &native) {
		return false
	}
	markers := StorageFullMarkers(repo.Connector)
	if len(markers) == 0 {
		return false
	}
	removals := storageFullRemovals(repo)
	return scanStorageFullLines(strings.NewReader(native.Output), repo.Engine, false, func(text string) bool {
		return textHasStorageFullMarker(text, markers, removals)
	})
}

// KopiaPolicyStorageFull reports whether a failed Kopia policy update ran out
// of space on the vault. Kopia policy commands use ordinary (not private)
// output, so the private-failure classifier never sees them; the command
// error text carries the native output instead, and this reads it with the
// same marker list.
//
// The text also carries names that come from the jobs rather than from the
// storage, and those must not match: Kopia's " - adding ..." lines and its
// "Setting policy for <target>" lines echo the job's own ignore rules, file
// names and policy targets back, so they are skipped; and policy targets of
// the form <job>@replicaro:<source> also appear inside Replicaro's own error
// wrapping next to native text, so the job source paths (sources) are taken
// out like the vault path.
func KopiaPolicyStorageFull(repo models.Repository, cause error, sources ...string) bool {
	if cause == nil || repo.Engine != KopiaID {
		return false
	}
	markers := StorageFullMarkers(repo.Connector)
	if len(markers) == 0 {
		return false
	}
	removals := storageFullRemovals(repo, sources...)
	for _, line := range strings.Split(cause.Error(), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "Setting policy for ") {
			continue
		}
		if textHasStorageFullMarker(line, markers, removals) {
			return true
		}
	}
	return false
}

// ReportStorageFullForTests records a match on ctx the way a failed backup
// does, for runner tests whose executor doesn't run an engine.
func ReportStorageFullForTests(ctx context.Context) {
	if found, _ := ctx.Value(storageFullReportKey{}).(*atomic.Bool); found != nil {
		found.Store(true)
	}
}
