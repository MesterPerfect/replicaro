package engines

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/models"
)

// BackupSourceReadFailure only changes how the result is presented. The wrapped
// requested operation is still a failure, with its original native exit cause.
// Keeping the two separate means a saved but incomplete snapshot cannot trigger
// retention or count toward successful-backup health and statistics.
//
// LockedFiles is set only when every source-read error the engine reported is
// a recognized lock error (see lockedFileErrorTexts). It lists the files that
// were left out and lets the run be shown as "completed, locked files
// skipped"; the native result is the same failure either way.
type BackupSourceReadFailure struct {
	SnapshotID  string
	LockedFiles []string
	Err         error
}

func (e *BackupSourceReadFailure) Error() string { return e.Err.Error() }
func (e *BackupSourceReadFailure) Unwrap() error { return e.Err }

func IsBackupSourceReadFailure(err error) bool {
	if partial, ok := err.(*BackupSourceReadFailure); ok {
		return partial.SnapshotID != "" && partial.Err != nil
	}
	// The executor joins stage errors. A source-read qualification cannot hide
	// a second failure from result persistence or occurrence bookkeeping.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !IsBackupSourceReadFailure(cause) {
				return false
			}
		}
		return true
	}
	if cause := errors.Unwrap(err); cause != nil {
		return IsBackupSourceReadFailure(cause)
	}
	return false
}

// BackupLockedFiles returns the skipped locked files when err consists only of
// source-read failures that each carry them, using the same walk as
// IsBackupSourceReadFailure. Anything else joined next to them (a follow-up
// failure, a script failure, a bookkeeping error) returns nil, so the run
// keeps the plain completed_with_issues presentation.
func BackupLockedFiles(err error) []string {
	if partial, ok := err.(*BackupSourceReadFailure); ok {
		if partial.SnapshotID == "" || partial.Err == nil || len(partial.LockedFiles) == 0 {
			return nil
		}
		return partial.LockedFiles
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var files []string
		for _, cause := range joined.Unwrap() {
			locked := BackupLockedFiles(cause)
			if len(locked) == 0 {
				return nil
			}
			files = append(files, locked...)
		}
		return files
	}
	if cause := errors.Unwrap(err); cause != nil {
		return BackupLockedFiles(cause)
	}
	return nil
}

// backupExit is the backup rule for trusting a native exit code: the requested
// child exited with exactly this code and no follow-up of any kind failed next
// to it. Backups are stricter than restores here on purpose; a saved-snapshot
// claim is only made from a completely clean exit record.
func backupExit(err error, code int) bool {
	followupErr, exited := requestedNativeExit(err, code)
	return exited && followupErr == nil
}

func resticPartialSnapshot(capture *command.CapturedOutput, runErr error) (models.Snapshot, bool) {
	if capture == nil || !backupExit(runErr, 3) {
		return models.Snapshot{}, false
	}
	reader, err := capture.OpenStdout()
	if err != nil {
		return models.Snapshot{}, false
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var snapshot models.Snapshot
	summaries := 0
	for scanner.Scan() {
		value, err := decodeUniqueJSON(scanner.Bytes())
		if err != nil {
			return models.Snapshot{}, false
		}
		row, ok := value.(map[string]any)
		if !ok {
			return models.Snapshot{}, false
		}
		if row["message_type"] != "summary" {
			continue
		}
		summaries++
		id, _ := row["snapshot_id"].(string)
		if !resticSnapshotIDPattern.MatchString(id) || id != strings.ToLower(id) || (row["dry_run"] != nil && row["dry_run"] != false) {
			return models.Snapshot{}, false
		}
		snapshot = parseResticBackupOutput(scanner.Text())
	}
	return snapshot, scanner.Err() == nil && summaries == 1 && snapshot.ID != ""
}

// readPath is the exact folder passed to "kopia snapshot create". It differs
// from the recorded snapshot source when the job has an "Update job source"
// alias: Kopia then reads the alias while --override-source records the
// job's immutable source.
func kopiaPartialSnapshot(capture *command.CapturedOutput, runErr error, readPath string) (models.Snapshot, bool) {
	if capture == nil || !backupExit(runErr, 1) {
		return models.Snapshot{}, false
	}
	snapshot, row, ok := kopiaSnapshotResult(capture)
	if !ok || !canonicalKopiaPartialID(row.ID) || row.RootEntry.Object == "" || row.IncompleteReason != "" || row.RootEntry.Summary.Failed <= 0 || int64(len(row.RootEntry.Summary.Errors)) != row.RootEntry.Summary.Failed {
		return models.Snapshot{}, false
	}
	for _, item := range row.RootEntry.Summary.Errors {
		if item.Path == "" || !(kopiaSourceReadError(item.Error) || kopiaSourcePathError(item.Error, snapshot.Source, item.Path) ||
			(readPath != "" && readPath != snapshot.Source && kopiaSourcePathError(item.Error, readPath, item.Path))) {
			return models.Snapshot{}, false
		}
	}
	stderr, err := capture.OpenStderr()
	if err != nil {
		return models.Snapshot{}, false
	}
	defer stderr.Close()
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var last string
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			last = line
		}
	}
	// In pinned Kopia, manifest output precedes the final flush. Only the final
	// source-error return proves flush did not supersede it with a publication
	// failure. Earlier progress/errors or a JSON snapshot ID alone prove neither.
	expected := fmt.Sprintf("Found %d fatal error(s) while snapshotting %s@%s:%s.", row.RootEntry.Summary.Failed, snapshot.NativeSourceUser, snapshot.NativeSourceHost, snapshot.Source)
	return snapshot, scanner.Err() == nil && last == expected
}

type kopiaSnapshotResultRow struct {
	ID               string `json:"id"`
	IncompleteReason string `json:"incomplete"`
	RootEntry        struct {
		Object  string `json:"obj"`
		Summary struct {
			Failed int64 `json:"numFailed"`
			Errors []struct {
				Path  string `json:"path"`
				Error string `json:"error"`
			} `json:"errors"`
		} `json:"summ"`
	} `json:"rootEntry"`
}

// kopiaSnapshotResult reads the snapshot result record from stdout.
func kopiaSnapshotResult(capture *command.CapturedOutput) (models.Snapshot, kopiaSnapshotResultRow, bool) {
	var row kopiaSnapshotResultRow
	reader, err := capture.OpenStdout()
	if err != nil {
		return models.Snapshot{}, row, false
	}
	// Read at most 8 MiB of stdout as a single snapshot result record. This is not
	// a repository listing and never a substitute for native repository
	// verification. Output that is too large or ambiguous leaves the backup
	// reported as failed.
	data, err := io.ReadAll(io.LimitReader(reader, 8*1024*1024+1))
	_ = reader.Close()
	if err != nil || len(data) > 8*1024*1024 {
		return models.Snapshot{}, row, false
	}
	value, err := decodeUniqueJSON(data)
	if err != nil {
		return models.Snapshot{}, row, false
	}
	compact, err := json.Marshal(value)
	if err != nil {
		return models.Snapshot{}, row, false
	}
	snapshot, err := parseKopiaSnapshot(string(compact))
	if err != nil || json.Unmarshal(compact, &row) != nil {
		return models.Snapshot{}, row, false
	}
	return snapshot, row, true
}

// Only pinned source-side error prefixes qualify. Object writer and repository
// errors can also appear in the manifest's fatal list, so an arbitrary item
// error must never be interpreted as an incomplete source capture.
func kopiaSourceReadError(message string) bool {
	return strings.HasPrefix(message, "unable to open file: unable to open local file: ") ||
		strings.HasPrefix(message, "cannot create iterator: unable to read directory: ") ||
		strings.HasPrefix(message, "unable to read symlink: ")
}

// The prefixes above were observed from pinned Kopia on Linux, where they wrap
// file-open, directory-read, and symlink-read failures. Windows source reads
// (and Linux reads that fail after a file opened) surface instead as raw Go
// *os.PathError text, "<op> <absolute path>: <message>", for example "read
// \\server\share\a.mp4: ..." or "GetFileInformationByHandleEx
// \\server\share\dir: ...". That shape alone proves nothing, because
// repository and object-writer failures can carry path errors too. It
// qualifies only when the absolute path is exactly the snapshot's native
// source root joined with the manifest item's own relative path, which ties
// the failure to reading that source item rather than to writing the
// repository.
//
// For a job with an "Update job source" alias the recorded source (set by
// --override-source) is the immutable source, but Kopia actually opened
// files under the alias, so its path errors name the alias. The caller
// therefore also accepts the exact folder it passed to Kopia as the root.
// That is the same proof, just against the root Kopia really read; every
// other condition (exact join, one path per item, count, final line) is
// unchanged. Do not widen this to prefix or case-insensitive matching.
func kopiaSourcePathError(message, sourceRoot, itemPath string) bool {
	op, rest, found := strings.Cut(message, " ")
	if !found || op == "" || strings.ContainsAny(op, ": \t\r\n\\/") {
		return false
	}
	windows := kopiaWindowsSourceRoot(sourceRoot)
	separator := "/"
	root := sourceRoot
	if windows {
		separator = `\`
		root = kopiaNormalizeWindowsPath(root)
		itemPath = strings.ReplaceAll(itemPath, "/", separator)
		rest = kopiaNormalizeWindowsPath(rest)
	} else if !strings.HasPrefix(root, "/") {
		return false
	}
	for _, segment := range strings.Split(itemPath, separator) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	base := strings.TrimRight(root, separator)
	if windows && base == "" {
		return false
	}
	prefix := base + separator + itemPath + ": "
	return strings.HasPrefix(rest, prefix) && strings.TrimSpace(rest[len(prefix):]) != ""
}

func kopiaWindowsSourceRoot(root string) bool {
	if strings.HasPrefix(root, `\\`) {
		return true
	}
	return len(root) >= 3 && root[1] == ':' && (root[2] == '\\' || root[2] == '/') &&
		((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z'))
}

// Windows may spell one path with either separator and with or without the
// extended-length prefix (\\?\UNC\server\share versus \\server\share).
func kopiaNormalizeWindowsPath(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + path[len(`\\?\UNC\`):]
	}
	return strings.TrimPrefix(path, `\\?\`)
}

func canonicalKopiaPartialID(id string) bool {
	if len(id) != 32 || id != strings.ToLower(id) {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// lockedFileErrorTexts lists, per GOOS of the computer the engine ran on, the
// exact native error texts that mean another program holds a source file
// locked. A backup whose every source-read error carries one of these texts is
// shown as "completed, locked files skipped" instead of plain completed with
// issues. Neither Restic nor Kopia reports the native error code, only Go's
// error text, so the text is all there is to match on.
//
// Windows has two entries, the Go text of ERROR_SHARING_VIOLATION (32, the
// file is open elsewhere without read sharing) and ERROR_LOCK_VIOLATION (33,
// a byte range is locked with LockFileEx). syscall.Errno.Error() asks Windows
// for the en-US text first, so on a system without English message resources
// the text is translated, nothing matches and the result stays plain
// completed with issues. "Access is denied." and "The system cannot find the
// path specified." are deliberately absent: they also mean permissions or a
// file that went away, not a lock.
//
// Linux, macOS and Docker have no entry. flock and fcntl locks are advisory
// there, so a lock held by another program doesn't stop the engine reading a
// local file and there is no deterministic lock error to recognize. Add an
// entry only with recorded output from the pinned engines on that platform.
var lockedFileErrorTexts = map[string][]string{
	"windows": {
		"The process cannot access the file because it is being used by another process.",
		"The process cannot access the file because another process has locked a portion of the file.",
	},
}

// lockedFilesOS is the GOOS whose lock texts the backup readers apply: the
// computer Replicaro and its engines run on. Tests set it to replay recorded
// output from another platform through the real Backup path.
var lockedFilesOS = runtime.GOOS

// sourceItemPath reports whether path is a file below root, spelled exactly as
// the engine was given root, with the platform's separator and no empty, "."
// or ".." segment. No case folding or alternative spellings: a path that
// doesn't match exactly simply doesn't qualify.
func sourceItemPath(root, path, goos string) bool {
	separator := "/"
	if goos == "windows" {
		if !kopiaWindowsSourceRoot(root) {
			return false
		}
		separator = `\`
	} else if !strings.HasPrefix(root, "/") {
		return false
	}
	base := strings.TrimRight(root, separator)
	if goos == "windows" && base == "" {
		return false
	}
	relative, found := strings.CutPrefix(path, base+separator)
	if !found || relative == "" || (goos == "windows" && strings.Contains(relative, "/")) {
		return false
	}
	for _, segment := range strings.Split(relative, separator) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// resticNativeItemPath is the path Restic hands to the operating system for a
// source item, which is the path that appears inside its error text. On
// Windows, Restic's fs.fixpath makes every path absolute and adds the
// extended-length prefix so long names work: C:\a becomes \\?\C:\a,
// \\server\share\a becomes \\?\UNC\server\share\a, and a path that already
// starts with \\?\ is left alone. The item field in the error record keeps the
// plain absolute path.
func resticNativeItemPath(item, goos string) string {
	if goos != "windows" {
		return item
	}
	switch {
	case strings.HasPrefix(item, `\\?\`):
		return item
	case strings.HasPrefix(item, `\\`):
		return `\\?\UNC\` + item[len(`\\`):]
	default:
		return `\\?\` + item
	}
}

// resticLockedFileRecord checks one stderr error record from "restic backup
// --json" ({"message_type":"error","error":{"message":...},"during":...,
// "item":...}) and returns its item when it is a recognized lock error for a
// file under source. The two accepted messages are the ones pinned Restic
// produces for a locked file:
//
//   - the file can't be opened (sharing violation):
//     "open <native path>: <text>";
//   - the file opened but reading it failed (locked byte range):
//     "failed to save <item>: read <native path>: <text>".
//
// Restic's archiver prefixes "<item>: " to an error whose text doesn't already
// contain the item. That never happens for the read form, and for the open
// form only when the item does not appear in the native path, which happens
// with the \\?\UNC\ spelling of a network path. The prefix is reproduced
// exactly.
func resticLockedFileRecord(record map[string]any, source, goos string) (string, bool) {
	if len(record) != 4 {
		return "", false
	}
	nested, _ := record["error"].(map[string]any)
	message, _ := nested["message"].(string)
	item, _ := record["item"].(string)
	during, _ := record["during"].(string)
	if len(nested) != 1 || message == "" || during != "archival" || !sourceItemPath(source, item, goos) {
		return "", false
	}
	native := resticNativeItemPath(item, goos)
	for _, text := range lockedFileErrorTexts[goos] {
		open := "open " + native + ": " + text
		if !strings.Contains(open, item) {
			open = item + ": " + open
		}
		if message == open || message == "failed to save "+item+": read "+native+": "+text {
			return item, true
		}
	}
	return "", false
}

// resticLockedFiles reads the stderr of a Restic backup that already
// qualified as a saved partial snapshot (exit 3 and one summary, see
// resticPartialSnapshot) and returns the skipped files when every error
// record is a recognized lock error. Restic reports each source item it could
// not read as one JSON error record on stderr and ends with one exit_error
// record. Its backup summary has no error count to compare against, so the
// rule is that stderr holds nothing but those records: any other line or
// record, a second exit record, or a single error that isn't a lock leaves
// the plain completed with issues result.
func resticLockedFiles(capture *command.CapturedOutput, source, goos string) []string {
	if capture == nil || len(lockedFileErrorTexts[goos]) == 0 {
		return nil
	}
	stderr, err := capture.OpenStderr()
	if err != nil {
		return nil
	}
	defer stderr.Close()
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var files []string
	exits := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		value, err := decodeUniqueJSON([]byte(line))
		if err != nil {
			return nil
		}
		record, _ := value.(map[string]any)
		switch record["message_type"] {
		case "error":
			item, ok := resticLockedFileRecord(record, source, goos)
			if !ok || exits > 0 {
				return nil
			}
			files = append(files, item)
		case "exit_error":
			exits++
			if code, _ := record["code"].(json.Number); code.String() != "3" {
				return nil
			}
		default:
			return nil
		}
	}
	if scanner.Err() != nil || exits != 1 || len(files) == 0 {
		return nil
	}
	return uniquePaths(files)
}

// kopiaLockedFileError reports whether one rootEntry.summ.errors[] item of a
// Kopia snapshot is a recognized lock error for root joined with the item's
// relative path. The two accepted messages are the ones pinned Kopia produces
// for a locked file, and they differ because the failure happens at a
// different call:
//
//   - a sharing violation fails the open, which Kopia's local filesystem and
//     uploader both wrap: "unable to open file: unable to open local file:
//     open <path>: <text>";
//   - a locked byte range lets the open succeed and fails the read, which
//     reaches the manifest as the bare Go error: "read <path>: <text>".
//
// The path is the root exactly as Kopia was given it, then the item path with
// the platform separator. Kopia's item paths always use "/".
func kopiaLockedFileError(message, root, itemPath, goos string) bool {
	separator := "/"
	if goos == "windows" {
		if strings.Contains(itemPath, `\`) {
			return false
		}
		separator = `\`
	}
	path := strings.TrimRight(root, separator) + separator + strings.ReplaceAll(itemPath, "/", separator)
	if !sourceItemPath(root, path, goos) {
		return false
	}
	for _, text := range lockedFileErrorTexts[goos] {
		if message == "unable to open file: unable to open local file: open "+path+": "+text || message == "read "+path+": "+text {
			return true
		}
	}
	return false
}

// kopiaLockedFiles reads the result of a Kopia backup that already qualified
// as a saved partial snapshot (see kopiaPartialSnapshot, which also checks the
// failed count against the error list and the final "Found N fatal error(s)"
// line) and returns the skipped files when every error item is a recognized
// lock error. As there, the root may be the recorded source or the folder
// Kopia actually read for a job with an "Update job source" alias.
func kopiaLockedFiles(capture *command.CapturedOutput, readPath, goos string) []string {
	if capture == nil || len(lockedFileErrorTexts[goos]) == 0 {
		return nil
	}
	snapshot, row, ok := kopiaSnapshotResult(capture)
	if !ok || row.RootEntry.Summary.Failed <= 0 || int64(len(row.RootEntry.Summary.Errors)) != row.RootEntry.Summary.Failed {
		return nil
	}
	files := make([]string, 0, len(row.RootEntry.Summary.Errors))
	for _, item := range row.RootEntry.Summary.Errors {
		root := snapshot.Source
		if !kopiaLockedFileError(item.Error, root, item.Path, goos) {
			root = readPath
			if readPath == "" || readPath == snapshot.Source || !kopiaLockedFileError(item.Error, root, item.Path, goos) {
				return nil
			}
		}
		separator := "/"
		if goos == "windows" {
			separator = `\`
		}
		files = append(files, strings.TrimRight(root, separator)+separator+strings.ReplaceAll(item.Path, "/", separator))
	}
	return uniquePaths(files)
}

var operationLogSectionHeader = regexp.MustCompile(`^\[(restic|kopia|replicaro) · ([^\]]+) · ([^\]]+)\]$`)

// kopiaLockedFilePath returns the absolute path inside one Kopia lock error
// message, in either form kopiaLockedFileError accepts. The path comes from the
// message rather than from the manifest's source.path because, for a job with
// an "Update job source" alias, source.path is the job's original folder while
// the message names the folder Kopia actually read.
func kopiaLockedFilePath(message string) (string, bool) {
	for _, texts := range lockedFileErrorTexts {
		for _, text := range texts {
			rest, found := strings.CutSuffix(message, ": "+text)
			if !found {
				continue
			}
			for _, prefix := range []string{"unable to open file: unable to open local file: open ", "read "} {
				if path, found := strings.CutPrefix(rest, prefix); found && path != "" {
					return path, true
				}
			}
		}
	}
	return "", false
}

// SkippedLockedFilesFromLog lists the files of a "completed, locked files
// skipped" backup from its saved operation log, so the list needs no stored
// state of its own. The caller checks the operation's issue kind first: that
// classification already proved every error in the native backup section is a
// lock error, so this only collects their paths. Restic's paths are the item
// fields of its stderr error records. Kopia's are the absolute paths inside
// the snapshot result's error messages (see kopiaLockedFilePath).
func SkippedLockedFilesFromLog(log io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(log)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	section := ""
	kopiaResultSeen := false
	var files []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if match := operationLogSectionHeader.FindStringSubmatch(line); match != nil {
			section = match[1] + " · " + match[2]
			continue
		}
		if !strings.HasPrefix(line, "{") {
			continue
		}
		switch section {
		case "restic · backup":
			value, err := decodeUniqueJSON([]byte(line))
			if err != nil {
				continue
			}
			record, _ := value.(map[string]any)
			if item, _ := record["item"].(string); record["message_type"] == "error" && item != "" {
				files = append(files, item)
			}
		case "kopia · backup and retention":
			if kopiaResultSeen {
				continue
			}
			kopiaResultSeen = true
			var row kopiaSnapshotResultRow
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			for _, item := range row.RootEntry.Summary.Errors {
				if path, ok := kopiaLockedFilePath(item.Error); ok {
					files = append(files, path)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return uniquePaths(files), nil
}

// uniquePaths drops repeated paths and keeps the first occurrence's order.
func uniquePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	unique := paths[:0]
	for _, path := range paths {
		if !seen[path] {
			seen[path] = true
			unique = append(unique, path)
		}
	}
	return unique
}
