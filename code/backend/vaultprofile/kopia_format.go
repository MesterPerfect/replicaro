package vaultprofile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/local/replicaro/engines"
	"github.com/local/replicaro/models"
)

// Reading and restoring Kopia's format blobs without Kopia.
//
// A Kopia password change saves both format blobs before Kopia first runs
// `repository change-password`, and recovery may put the saved kopia.blobcfg
// back (see PasswordRotationKopiaFormat). Recovery needs this precisely when
// neither password opens the repository, so it can't ask Kopia; it reads and
// writes the objects through the same storage path Replicaro already uses for
// the vault root: the folder itself for a filesystem vault, and otherwise
// pinned rclone's base remote for the vault root, the remote BaseRemoteForVault
// describes. That is also why the names are checked against `kopia blob show`
// before the change: only a name whose bytes match what Kopia reports is ever
// read or written later.
//
// Nothing here encrypts or decrypts anything. kopia.blobcfg is copied as the
// bytes Kopia wrote.

// MaximumKopiaFormatBlobBytes bounds every format blob read. Pinned Kopia
// writes a kopia.repository of about 1 KiB and a kopia.blobcfg of a few dozen
// bytes, so anything near the bound is not a format blob.
const MaximumKopiaFormatBlobBytes = 16 << 10

// KopiaFormatBlobNames lists the object names a Kopia storage backend gives a
// format blob at the vault root. Measured with pinned Kopia: filesystem, SFTP
// and WebDAV add ".f" and keep these two blobs unsharded at the root; S3
// stores the bare blob ID under the vault prefix. Which one a vault uses, on
// these and on every other backend, is decided before the change by comparing
// the bytes with `kopia blob show`, never from the connector.
func KopiaFormatBlobNames(blobID string) []string {
	return []string{blobID + ".f", blobID}
}

func validKopiaFormatBlobName(name string) bool {
	return slices.Contains(KopiaFormatBlobNames(engines.KopiaRepositoryBlob), name) ||
		slices.Contains(KopiaFormatBlobNames(engines.KopiaBlobcfgBlob), name)
}

// ReadKopiaFormatBlob reads one Kopia format blob from the vault's storage.
// found is false only when storage positively reports no object of that name;
// any other failure is an error. A filesystem read is bounded by ctx.
func ReadKopiaFormatBlob(ctx context.Context, repo models.Repository, name string) (data []byte, found bool, err error) {
	if !validKopiaFormatBlobName(name) {
		return nil, false, fmt.Errorf("invalid Kopia format blob name")
	}
	if repo.Connector == "fs" {
		return readLocalKopiaFormatBlob(ctx, repo.Location, name)
	}
	store := Store{Repository: repo}
	session, err := store.session(ctx)
	if err != nil {
		return nil, false, err
	}
	defer store.finishSession(ctx, session, &err)
	return readRemoteKopiaFormatBlob(ctx, session, name)
}

// RestoreKopiaBlobcfg writes data as the vault's kopia.blobcfg object and
// reads it back. It only ever writes one of the two kopia.blobcfg names.
//
// The filesystem write is a temporary file in the vault folder, fsync,
// rename over the blob and a best-effort folder fsync, with mode 0600 as
// Kopia creates its own files here; a crash leaves the old or the new blob,
// and at most the temporary file, whose name Kopia ignores (it lists only names ending in
// ".f"). It is deliberately not bounded by ctx the way the reads are: a write
// that finished after the caller gave up and released the vault lock could
// land after a later rerun of Kopia and undo it. The read just before it
// showed the folder answering.
//
// Other connectors upload with `rclone rcat`. The read-back is what counts: a
// cut-off upload either fails it or leaves a blob that the next recovery
// attempt finds still different from the saved bytes and writes again.
//
// written reports whether the bytes reached the vault (the rename, or a
// finished rcat), even when the read-back after it fails. The caller then
// still says that Replicaro wrote to the repository, and a read-back cut off
// by its deadline is something the next attempt goes on from, not a failed
// write-back.
func RestoreKopiaBlobcfg(ctx context.Context, repo models.Repository, name string, data []byte) (written bool, err error) {
	if !slices.Contains(KopiaFormatBlobNames(engines.KopiaBlobcfgBlob), name) ||
		len(data) == 0 || len(data) > MaximumKopiaFormatBlobBytes {
		return false, fmt.Errorf("invalid Kopia storage configuration restore")
	}
	if repo.Connector == "fs" {
		if err := writeLocalKopiaBlobcfg(repo.Location, name, data); err != nil {
			return false, fmt.Errorf("write %s: %w", name, err)
		}
		readBack, found, err := readLocalKopiaFormatBlob(ctx, repo.Location, name)
		return true, confirmRestoredKopiaBlobcfg(name, data, readBack, found, err)
	}
	store := Store{Repository: repo}
	session, err := store.session(ctx)
	if err != nil {
		return false, err
	}
	defer store.finishSession(ctx, session, &err)
	return restoreRemoteKopiaBlobcfg(ctx, session, name, data)
}

func restoreRemoteKopiaBlobcfg(ctx context.Context, session *storeSession, name string, data []byte) (bool, error) {
	if _, err := session.runWithInput(ctx, "kopia storage configuration restore", string(data),
		"rcat", baseRootObject(session.root, name)); err != nil {
		return false, fmt.Errorf("write %s: %w", name, err)
	}
	readBack, found, err := readRemoteKopiaFormatBlob(ctx, session, name)
	return true, confirmRestoredKopiaBlobcfg(name, data, readBack, found, err)
}

func confirmRestoredKopiaBlobcfg(name string, data, readBack []byte, found bool, err error) error {
	if err != nil {
		return fmt.Errorf("read back %s: %w", name, err)
	}
	if !found || !bytes.Equal(readBack, data) {
		return fmt.Errorf("the restored %s reads back differently", name)
	}
	return nil
}

func readLocalKopiaFormatBlob(ctx context.Context, directory, name string) ([]byte, bool, error) {
	type result struct {
		data  []byte
		found bool
	}
	read, err := engines.ReadWithin(ctx, func() (result, error) {
		file, err := os.Open(filepath.Join(directory, name))
		if errors.Is(err, os.ErrNotExist) {
			return result{}, nil
		}
		if err != nil {
			return result{}, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return result{}, err
		}
		if !info.Mode().IsRegular() || info.Size() > MaximumKopiaFormatBlobBytes {
			return result{}, fmt.Errorf("%s is not a Kopia format blob", name)
		}
		data, err := io.ReadAll(io.LimitReader(file, MaximumKopiaFormatBlobBytes+1))
		if err != nil {
			return result{}, err
		}
		if len(data) > MaximumKopiaFormatBlobBytes {
			return result{}, fmt.Errorf("%s is not a Kopia format blob", name)
		}
		return result{data: data, found: true}, nil
	})
	return read.data, read.found, err
}

// readRemoteKopiaFormatBlob stats the object before reading it because
// `rclone cat` of a missing object prints nothing and exits 0 on bucket
// remotes and on the local backend alike; the stat (which also handles a
// bucket's directory answer for a missing name) is what tells "missing" from
// "empty", and the size check catches an object replaced in between.
func readRemoteKopiaFormatBlob(ctx context.Context, session *storeSession, name string) ([]byte, bool, error) {
	stat, found, err := statObject(ctx, session, baseRootObject(session.root, name))
	if err != nil || !found {
		return nil, false, err
	}
	if stat.Size < 0 || stat.Size > MaximumKopiaFormatBlobBytes {
		return nil, true, fmt.Errorf("%s is not a Kopia format blob", name)
	}
	output, err := session.runWithInput(ctx, "kopia format blob read", name+"\n",
		"cat", session.root, "--files-from-raw", "-", "--no-traverse", "--count", strconv.Itoa(MaximumKopiaFormatBlobBytes+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(output)) != stat.Size {
		return nil, true, fmt.Errorf("%s changed while it was read", name)
	}
	return []byte(output), true, nil
}

var syncKopiaBlobcfgDirectory = syncPasswordRotationDirectory

// writeLocalKopiaBlobcfg replaces directory/name atomically; see
// RestoreKopiaBlobcfg.
func writeLocalKopiaBlobcfg(directory, name string, data []byte) (err error) {
	temp := filepath.Join(directory, name+".replicaro-restore.tmp")
	if err := os.Remove(temp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(temp)
		}
	}()
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
	if err := os.Rename(temp, filepath.Join(directory, name)); err != nil {
		return err
	}
	// The folder fsync only makes the rename survive a power cut; the bytes
	// are already in place. Some shares refuse it (CIFS answers EINVAL), and
	// failing here would turn a write-back that worked into "manual recovery
	// is required". The read-back and the password check that follow decide
	// instead.
	_ = syncKopiaBlobcfgDirectory(directory)
	return nil
}

// baseRootObject names an object directly under the vault root on the base
// remote. A WebDAV root is the bare remote "base:", where a slash would make
// the path absolute on the server.
func baseRootObject(root, name string) string {
	if strings.HasSuffix(root, ":") {
		return root + name
	}
	return strings.TrimSuffix(root, "/") + "/" + name
}
