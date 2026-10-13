package appdata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Executable is a program bundled inside Replicaro's own binary that has to
// be installed under the application folder before it can run: Restic,
// Kopia, rclone and the storage helper.
type Executable struct {
	// Open returns a fresh reader over the bundled bytes. It is called once
	// per pass over them, so the bytes are streamed instead of being copied
	// into memory; the engines are around 60 and 100 MB.
	Open func() (io.ReadCloser, error)
	// SHA256 is the build-time checksum of the bundled bytes, in hex.
	SHA256 string
}

// ExecutableFromFS reads the bundled bytes from an embedded file system.
func ExecutableFromFS(fsys fs.FS, name, checksum string) Executable {
	return Executable{
		Open:   func() (io.ReadCloser, error) { return fsys.Open(name) },
		SHA256: checksum,
	}
}

// ExecutableFromBytes reads the bundled bytes from a slice that is already in
// memory, such as a //go:embed []byte variable.
func ExecutableFromBytes(data []byte, checksum string) Executable {
	return Executable{
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		SHA256: checksum,
	}
}

// installedExecutables remembers, for each destination installed or verified
// in this run, the size and mode of the file that was put there. The mutex
// also makes installs one at a time: two callers resolving the same program at
// once would otherwise both write a temporary copy and race to rename it, and
// on Windows the rename fails while the other caller still has the file open.
var installedExecutables = struct {
	sync.Mutex
	files map[string]installedFile
}{files: map[string]installedFile{}}

type installedFile struct {
	size int64
	mode fs.FileMode
}

// EnsureExecutable returns directory/fileName holding source's bytes,
// installing it with InstallExecutable the first time a run needs it. After
// that, each call only checks that the path still has the installed size and
// mode, which costs one Lstat instead of re-reading and hashing the whole
// program on every engine command. A file that is gone, replaced by a link or
// folder, or changed in size or mode gets the full install again. The mode is
// part of the check so a program that lost its execute permission is set back
// to 0700 by the next call, instead of every command failing until Replicaro
// restarts.
//
// A failed install is not remembered, so the next call tries again from the
// start, including the check of whatever is already at the path.
//
// There's deliberately no per-call checksum here. Within a run, the only
// things that can change the file without changing its size are someone
// editing Replicaro's files on purpose or disk corruption, and neither is
// worth hashing about 100 MB per command for; a new run hashes it again on
// first use. The storage helper is different: it keeps its own check of the
// checksum before every launch (see storagehelper.Runner) and calls
// InstallExecutable directly.
func EnsureExecutable(source Executable, directory, fileName string) (string, error) {
	destination := filepath.Join(directory, fileName)
	installedExecutables.Lock()
	defer installedExecutables.Unlock()
	if installed, ok := installedExecutables.files[destination]; ok {
		// The recorded mode is a regular file's, so an equal mode also rules
		// out a link or folder at the path.
		if info, err := os.Lstat(destination); err == nil && info.Mode() == installed.mode && info.Size() == installed.size {
			return destination, nil
		}
		delete(installedExecutables.files, destination)
	}
	if err := installExecutable(source, destination); err != nil {
		return "", err
	}
	info, err := os.Lstat(destination)
	if err != nil {
		return "", fmt.Errorf("inspect installed executable: %w", err)
	}
	installedExecutables.files[destination] = installedFile{size: info.Size(), mode: info.Mode()}
	return destination, nil
}

// InstallExecutable checks source's bytes against their checksum and makes
// directory/fileName a regular, owner-only file with exactly those bytes. The
// directory must already exist.
//
// A regular file that already has the right bytes is kept and only set back
// to mode 0700. Anything else at the path (a missing file, wrong bytes, a file
// that can't be read or re-moded, a link, or another non-regular entry) is
// replaced: the bytes go into a private temporary file next to it, which is
// flushed to disk and then renamed over the path. The rename swaps out a link
// itself instead of writing through it. A folder at the path can't be renamed
// over, so that case fails with the filesystem's own error. The installed file
// is hashed once more before it's returned.
//
// The checksum is what protects against a corrupted, truncated or stale
// program. There are intentionally no owner or link checks on the folders or
// the file: those only matter against someone with access to the computer
// tampering with Replicaro's files, which Replicaro doesn't defend against,
// and they break ordinary setups such as symlinked home folders. Don't add
// them back without a product decision.
func InstallExecutable(source Executable, directory, fileName string) (string, error) {
	destination := filepath.Join(directory, fileName)
	if err := installExecutable(source, destination); err != nil {
		return "", err
	}
	return destination, nil
}

func installExecutable(source Executable, destination string) error {
	size, err := bundledSize(source)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil && info.Mode().IsRegular() && info.Size() == size &&
		VerifyExecutable(destination, source.SHA256) == nil && os.Chmod(destination, 0o700) == nil {
		return nil
	}

	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+installTemporaryMarker+"*")
	if err != nil {
		return fmt.Errorf("create temporary executable: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	fail := func(cause error) error {
		_ = temporary.Close()
		return cause
	}
	// On Windows Chmod only clears the read-only attribute; the file inherits
	// the application folder's protected DACL like everything else Replicaro
	// creates there.
	if err := temporary.Chmod(0o700); err != nil {
		return fail(fmt.Errorf("secure temporary executable: %w", err))
	}
	if err := copyBundled(temporary, source); err != nil {
		return fail(fmt.Errorf("write temporary executable: %w", err))
	}
	// Flush before the rename on every platform, Windows included, so a crash
	// right after the install can't leave a renamed but empty or partly
	// written program behind.
	if err := temporary.Sync(); err != nil {
		return fail(fmt.Errorf("flush temporary executable: %w", err))
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary executable: %w", err)
	}
	if err := AtomicReplace(temporaryPath, destination); err != nil {
		return fmt.Errorf("atomically install executable: %w", err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		return fmt.Errorf("secure installed executable: %w", err)
	}
	if info, err := os.Lstat(destination); err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return fmt.Errorf("verify installed executable: not a regular file of the bundled size")
	}
	if err := VerifyExecutable(destination, source.SHA256); err != nil {
		return fmt.Errorf("verify installed executable: %w", err)
	}
	return nil
}

// installTemporaryMarker is in the name of every temporary copy
// installExecutable writes: "." + the program's file name + this marker + the
// random digits os.CreateTemp adds. Older Windows versions wrote the same
// name without the leading dot (for example kopia.exe.updated-123), and
// installTemporaryName matches those leftovers too.
const installTemporaryMarker = ".updated-"

func installTemporaryName(name string) bool {
	program, digits, found := strings.Cut(name, installTemporaryMarker)
	if !found || strings.TrimPrefix(program, ".") == "" || digits == "" {
		return false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// RemoveStaleInstallTemporaries deletes the temporary copies installExecutable
// leaves in the given application-data folders when a run stops between
// writing one and renaming it into place (a crash, a forced quit, or power
// loss); an ordinary failure removes its own copy. It is meant for startup,
// before anything installs a program, so every copy it finds belongs to an
// earlier run. Folders that don't exist are skipped and nothing is created.
// Each removal is os.Remove, which deletes a link rather than its target.
func RemoveStaleInstallTemporaries(folders ...string) error {
	root, err := rootDirectory()
	if err != nil {
		return err
	}
	var result error
	for _, folder := range folders {
		clean, err := safeRelativeName(folder)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		directory := filepath.Join(root, clean)
		entries, err := os.ReadDir(directory)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !installTemporaryName(entry.Name()) {
				continue
			}
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

// bundledSize hashes the bundled bytes and returns their length, or an error
// if they don't match the build checksum.
func bundledSize(source Executable) (int64, error) {
	if source.Open == nil {
		return 0, fmt.Errorf("bundled executable is unavailable")
	}
	reader, err := source.Open()
	if err != nil {
		return 0, fmt.Errorf("open bundled executable: %w", err)
	}
	defer reader.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, reader)
	if err != nil {
		return 0, fmt.Errorf("read bundled executable: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), source.SHA256) {
		return 0, fmt.Errorf("bundled bytes do not match their build checksum")
	}
	return size, nil
}

func copyBundled(destination io.Writer, source Executable) error {
	reader, err := source.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	_, err = io.Copy(destination, reader)
	return err
}

// VerifyExecutable reports whether path is a regular file whose SHA-256 is
// expected. It only reads, so it follows a link like any other program would
// and hashes whatever is there. The Stat comes first so a folder or a FIFO
// left at the path fails here instead of blocking the open.
func VerifyExecutable(path, expected string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("executable is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expected) {
		return fmt.Errorf("executable checksum mismatch")
	}
	return nil
}
