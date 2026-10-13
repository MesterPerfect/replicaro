package engines

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/local/replicaro/command"
	"github.com/local/replicaro/models"
)

// These are native DirManifest fields, not a replacement repository format.
// Keep summaries raw: missing or unusable counters disable the text fast path,
// while native error details remain available in the unchanged captured output.
type kopiaDirectoryManifest struct {
	Stream  string                `json:"stream"`
	Entries []kopiaDirectoryEntry `json:"entries"`
	Summary json.RawMessage       `json:"summary"`
}
type kopiaDirectoryEntry struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	Mode    string          `json:"mode"`
	Size    int64           `json:"size"`
	Mtime   string          `json:"mtime"`
	Object  string          `json:"obj"`
	Summary json.RawMessage `json:"summ"`
}

func readKopiaDirectory(ctx context.Context, repo models.Repository, object string, run kopiaCapturedCommandRunner) (*kopiaDirectoryManifest, string, error) {
	capture, out, err := run(ctx, repo, []string{"show", object}, command.NoTotalDeadline)
	if capture != nil {
		defer capture.Close()
	}
	if err != nil {
		return nil, out, err
	}
	stdout, err := capture.OpenStdout()
	if err != nil {
		return nil, out, kopiaOutputProcessingFailure(err)
	}
	manifest, err := parseKopiaDirectory(stdout)
	_ = stdout.Close()
	if err != nil {
		return nil, out, kopiaOutputProcessingFailure(err)
	}
	duplicates := manifest.duplicateNames()
	if len(duplicates) == 0 {
		return manifest, out, nil
	}
	listed, listOut, err := kopiaListedObjects(ctx, repo, object, run)
	out += listOut
	if err != nil {
		return nil, out, err
	}
	if err := manifest.keepListedEntries(duplicates, listed); err != nil {
		return nil, out, kopiaOutputProcessingFailure(err)
	}
	log.Printf("Kopia directory %s in vault %s stores %d duplicated names; using the entry Kopia's own listing shows for each",
		object, repo.ID, len(duplicates))
	return manifest, out, nil
}

// duplicateNames lists the names this directory stores more than once.
// Kopia replaces bytes that aren't valid UTF-8 with U+FFFD when it records a
// name, so two names that differ only in such bytes are both stored under one
// name. Kopia itself then lists and restores only one of them for that name.
func (manifest *kopiaDirectoryManifest) duplicateNames() map[string]bool {
	seen := make(map[string]bool, len(manifest.Entries))
	duplicates := map[string]bool{}
	for _, entry := range manifest.Entries {
		if seen[entry.Name] {
			duplicates[entry.Name] = true
		}
		seen[entry.Name] = true
	}
	return duplicates
}

// kopiaListedEntry is one record of Kopia's own long listing of a directory:
// the mode column as Kopia prints it and the object ID.
type kopiaListedEntry struct {
	mode, object string
}

// kopiaListedObjects runs Kopia's own listing of one directory object and
// returns the records it shows for each name.
func kopiaListedObjects(ctx context.Context, repo models.Repository, object string, run kopiaCapturedCommandRunner) (map[string][]kopiaListedEntry, string, error) {
	capture, out, err := run(ctx, repo, []string{"list", object, "--long"}, command.NoTotalDeadline)
	if capture != nil {
		defer capture.Close()
	}
	if err != nil {
		return nil, out, err
	}
	stdout, err := capture.OpenStdout()
	if err != nil {
		return nil, out, kopiaOutputProcessingFailure(err)
	}
	defer stdout.Close()
	listed := map[string][]kopiaListedEntry{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for scanner.Scan() {
		// A name with a line break splits its record, and a piece that
		// doesn't parse is skipped. A piece that does parse can only add a
		// record, and a name with more than one record is refused below.
		mode, objectID, name, parseErr := parseKopiaLongRecord(scanner.Text())
		if parseErr != nil {
			continue
		}
		if strings.HasPrefix(mode, "d") {
			name = strings.TrimSuffix(name, "/")
		}
		listed[name] = append(listed[name], kopiaListedEntry{mode: mode, object: objectID})
	}
	if err := scanner.Err(); err != nil {
		return nil, out, kopiaOutputProcessingFailure(err)
	}
	return listed, out, nil
}

// keepListedEntries keeps, for each duplicated name, the one entry Kopia's
// own listing shows, so File History offers what a Kopia restore gives. The
// listing must show exactly one record for the name, and that record must
// pick out one stored entry (see listedEntry). Anything else is refused
// rather than guessed.
func (manifest *kopiaDirectoryManifest) keepListedEntries(duplicates map[string]bool, listed map[string][]kopiaListedEntry) error {
	chosen := make(map[string]int, len(duplicates))
	for name := range duplicates {
		records := listed[name]
		if len(records) != 1 {
			return fmt.Errorf("parse Kopia directory: Kopia's listing does not identify one entry for a duplicated name")
		}
		index, err := manifest.listedEntry(name, records[0])
		if err != nil {
			return err
		}
		chosen[name] = index
	}
	keep := make([]kopiaDirectoryEntry, 0, len(manifest.Entries))
	for index, entry := range manifest.Entries {
		if position, duplicated := chosen[entry.Name]; !duplicated || position == index {
			keep = append(keep, entry)
		}
	}
	manifest.Entries = keep
	return nil
}

// listedEntry returns the index of the stored entry named name that Kopia's
// listing record shows. Entries are matched by object ID. Two names with the
// same contents share an object ID, so when several entries match, the mode
// Kopia lists decides between them. Entries that still match are the same
// to the index (name, mode, size and type), so the first one is used.
func (manifest *kopiaDirectoryManifest) listedEntry(name string, record kopiaListedEntry) (int, error) {
	var candidates []int
	for index, entry := range manifest.Entries {
		if entry.Name == name && entry.Object == record.object {
			candidates = append(candidates, index)
		}
	}
	if len(candidates) > 1 {
		sameMode := candidates[:0:0]
		for _, index := range candidates {
			converted, err := manifest.Entries[index].snapshotEntry("")
			if err != nil {
				return 0, err
			}
			if converted.Mode == record.mode {
				sameMode = append(sameMode, index)
			}
		}
		candidates = sameMode
	}
	if len(candidates) == 0 {
		return 0, fmt.Errorf("parse Kopia directory: Kopia's listing matches no stored entry for a duplicated name")
	}
	first := manifest.Entries[candidates[0]]
	converted, err := first.snapshotEntry("")
	if err != nil {
		return 0, err
	}
	for _, index := range candidates[1:] {
		other, err := manifest.Entries[index].snapshotEntry("")
		if err != nil || other != converted || manifest.Entries[index].Type != first.Type {
			return 0, fmt.Errorf("parse Kopia directory: Kopia's listing matches more than one different entry for a duplicated name")
		}
	}
	return candidates[0], nil
}

func parseKopiaDirectory(reader io.Reader) (*kopiaDirectoryManifest, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	unique, _, err := readUniqueJSONValueAtPath(decoder, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("parse Kopia directory: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("parse Kopia directory: trailing data")
	}
	fields, ok := unique.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parse Kopia directory: manifest is not an object")
	}
	if _, present := fields["entries"]; !present {
		return nil, fmt.Errorf("parse Kopia directory: entries are missing")
	}
	data, err := json.Marshal(unique)
	if err != nil {
		return nil, err
	}
	var manifest kopiaDirectoryManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse Kopia directory: %w", err)
	}
	if manifest.Stream != "kopia:directory" {
		return nil, fmt.Errorf("parse Kopia directory: unexpected native stream")
	}
	// A name stored more than once is resolved against Kopia's own listing in
	// readKopiaDirectory (see duplicateNames).
	for _, entry := range manifest.Entries {
		if entry.Name == "" || entry.Name == "." || entry.Name == ".." || strings.ContainsAny(entry.Name, "/\x00") {
			return nil, fmt.Errorf("parse Kopia directory: invalid native name %q", entry.Name)
		}
		if entry.Object == "" && entry.Type != "" || strings.TrimSpace(entry.Object) != entry.Object || strings.ContainsAny(entry.Object, "/\x00\r\n") || strings.HasPrefix(entry.Object, "-") {
			return nil, fmt.Errorf("parse Kopia directory: invalid native object identity")
		}
		if _, err := entry.snapshotEntry(""); err != nil {
			return nil, err
		}
	}
	return &manifest, nil
}

func (entry kopiaDirectoryEntry) snapshotEntry(prefix string) (models.SnapshotEntry, error) {
	var mode os.FileMode
	if entry.Mode != "" {
		parsed, err := strconv.ParseUint(entry.Mode, 8, 32)
		if err != nil {
			return models.SnapshotEntry{}, fmt.Errorf("parse Kopia directory: invalid native mode")
		}
		mode = os.FileMode(parsed)
	}
	switch entry.Type {
	case "f":
	case "d":
		mode |= os.ModeDir
	case "s":
		mode |= os.ModeSymlink
	case "":
		mode = 0 // Native snapshotfs reports zero mode; selected restore still rejects this type.
	default:
		return models.SnapshotEntry{}, fmt.Errorf("parse Kopia directory: unsupported native entry type %q", entry.Type)
	}
	if entry.Size < 0 {
		return models.SnapshotEntry{}, fmt.Errorf("parse Kopia directory: negative size")
	}
	if entry.Mtime != "" {
		if _, err := time.Parse(time.RFC3339Nano, entry.Mtime); err != nil {
			return models.SnapshotEntry{}, fmt.Errorf("parse Kopia directory: invalid mtime")
		}
	}

	// Kopia's snapshotfs loader replaces a directory's stored FileSize with
	// DirSummary.TotalFileSize before list prints it. Match that native view.
	size := entry.Size
	if entry.Type == "d" && len(entry.Summary) > 0 && string(entry.Summary) != "null" {
		var summary struct {
			Size int64 `json:"size"`
		}
		if err := json.Unmarshal(entry.Summary, &summary); err != nil || summary.Size < 0 {
			return models.SnapshotEntry{}, fmt.Errorf("parse Kopia directory: invalid native directory size")
		}
		size = summary.Size
	}
	return models.SnapshotEntry{Name: entry.Name, Path: prefix + entry.Name, Mode: mode.String(), Size: strconv.FormatInt(size, 10), IsDir: entry.Type == "d"}, nil
}

func (manifest *kopiaDirectoryManifest) selectedType(basename string) (kopiaSelectedEntryType, error) {
	for _, entry := range manifest.Entries {
		if entry.Name != basename {
			continue
		}
		switch entry.Type {
		case "f":
			return kopiaSelectedRegularFile, nil
		case "d":
			return kopiaSelectedDirectory, nil
		case "s":
			return kopiaSelectedSymlink, nil
		default:
			return kopiaSelectedUnsupported, nil
		}
	}
	return "", fmt.Errorf("kopia selected path %q was not found in fresh snapshot metadata", basename)
}

func kopiaSummaryEntryCount(raw json.RawMessage) (int64, bool) {
	var summary map[string]json.RawMessage
	if json.Unmarshal(raw, &summary) != nil {
		return 0, false
	}
	var total int64
	for _, key := range []string{"files", "dirs", "symlinks"} {
		count, ok := exactNonnegativeJSONInteger(summary[key])
		if !ok || key == "dirs" && count == 0 || count > math.MaxInt64-total {
			return 0, false
		}
		total += count
	}
	return total - 1, true // Native directories include the requested root.
}

// goFileModeTypeLetters are the type and flag letters Go's fs.FileMode.String
// prints before the permission bits, in its order. Kopia prints modes with
// that method, so a setuid file is "urwxr-xr-x" and a sticky directory is
// "dtrwxrwxrwx", and the per-directory JSON fallback renders the same string.
const goFileModeTypeLetters = "dalTLDpSugct?"

// canonicalGoFileModeString reports whether mode is what
// fs.FileMode.String prints for some mode: either "-" or letters from
// goFileModeTypeLetters in their order, then nine permission characters. A
// listing column that is not such a string means the record is misframed.
func canonicalGoFileModeString(mode string) bool {
	if len(mode) < 10 {
		return false
	}
	prefix, permissions := mode[:len(mode)-9], mode[len(mode)-9:]
	for index := range permissions {
		if permissions[index] != "rwx"[index%3] && permissions[index] != '-' {
			return false
		}
	}
	if prefix == "-" {
		return true
	}
	next := 0
	for _, letter := range []byte(prefix) {
		position := strings.IndexByte(goFileModeTypeLetters[next:], letter)
		if position < 0 {
			return false
		}
		next += position + 1
	}
	return true
}

// Count raw LF records before any deduplication. A filename containing LF can
// manufacture another perfectly valid record; syntax alone cannot detect that.
// The native summary is a framing check, not a new integrity guarantee.
func parseCheckedKopiaEntries(reader io.Reader, summary json.RawMessage) ([]models.SnapshotEntry, error) {
	expected, usable := kopiaSummaryEntryCount(summary)
	if !usable {
		return nil, fmt.Errorf("Kopia native summary is unavailable or unusable")
	}
	buffered := bufio.NewReader(reader)
	var entries []models.SnapshotEntry
	seen := map[string]bool{}
	var records int64
	for {
		line, err := buffered.ReadString('\n')
		if err == io.EOF && line == "" {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Kopia long listing is not LF terminated: %w", err)
		}
		records++
		if records > expected {
			return nil, fmt.Errorf("Kopia long listing record count differs from native summary")
		}
		line = strings.TrimSuffix(line, "\n")
		mode, name, err := parseKopiaLongEntry(line)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(line)
		if len(fields) < 7 || !canonicalGoFileModeString(mode) {
			return nil, fmt.Errorf("Kopia long listing has a nonstandard mode")
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("Kopia long listing has invalid size")
		}
		if _, err := time.Parse("2006-01-02 15:04:05", fields[2]+" "+fields[3]); err != nil {
			return nil, fmt.Errorf("Kopia long listing has invalid time")
		}
		if mode[0] == 'd' {
			if !strings.HasSuffix(name, "/") {
				return nil, fmt.Errorf("Kopia directory record has no slash")
			}
			name = strings.TrimSuffix(name, "/")
		}
		if normalized, err := normalizeSnapshotRelativePath(name); err != nil || normalized == "" || seen[name] {
			return nil, fmt.Errorf("Kopia long listing has an invalid or duplicate path")
		}
		seen[name] = true
		parts := strings.Split(name, "/")
		entries = append(entries, models.SnapshotEntry{Name: parts[len(parts)-1], Path: name, Mode: mode, Size: fields[1], IsDir: mode[0] == 'd'})
	}
	if records != expected {
		return nil, fmt.Errorf("Kopia long listing record count differs from native summary")
	}
	return entries, nil
}
