package vaultprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/local/replicaro/appdata"
	"github.com/local/replicaro/models"
)

const MaximumPasswordChangeProfiles = 256

// A complete inventory can contain two 4 MiB roots and canonical/previous
// generations for 256 16 MiB profiles: 8,200 MiB. Rotation may retain two
// complete data-bearing inventories, accepting a theoretical 16,400 MiB
// (about 16.02 GiB) peak plus object and native-command overhead.
const MaximumPasswordRotationBytes = int64(2*MaximumRootDecryptedSize + 2*MaximumPasswordChangeProfiles*MaximumProfileDecryptedSize)
const maximumPasswordRotationManifestBytes = 1 << 20

var passwordRotationFault = func(string) error { return nil }

type PasswordRotationObject struct {
	Name       string `json:"name"`
	Role       string `json:"role"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	StagedFile string `json:"stagedFile,omitempty"`
	Data       []byte `json:"-"`
}

type PasswordRotationInventory struct {
	Version       int                      `json:"version"`
	RepositoryID  string                   `json:"repositoryId"`
	OperationUUID string                   `json:"operationUUID"`
	Objects       []PasswordRotationObject `json:"objects"`
	Pending       []string                 `json:"pending,omitempty"`
}

func rotationStoreForObject(base Store, name string) (Store, error) {
	if name == canonicalRootObject || name == previousRootObject || strings.HasPrefix(name, pendingRootPrefix) {
		return base, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != "profiles" || !exactUUID(parts[1]) {
		return Store{}, fmt.Errorf("protected object path is invalid")
	}
	return base.ForProfile(parts[1]), nil
}

func rotationRole(name string) string {
	switch {
	case name == canonicalRootObject:
		return "root_canonical"
	case name == previousRootObject:
		return "root_previous"
	case strings.HasSuffix(name, "/profile.replicaro"):
		return "profile_canonical"
	default:
		return "profile_previous"
	}
}

func validRotationObjectName(name string) bool {
	if name == canonicalRootObject || name == previousRootObject {
		return true
	}
	parts := strings.Split(name, "/")
	return len(parts) == 3 && parts[0] == "profiles" && exactUUID(parts[1]) &&
		(parts[2] == "profile.replicaro" || parts[2] == "profile.replicaro.previous")
}

func validPendingRotationName(name string) bool {
	marker := ".pending."
	index := strings.LastIndex(name, marker)
	if index < 0 {
		return false
	}
	parsed, err := uuid.Parse(name[index+len(marker):])
	return err == nil && parsed.String() == name[index+len(marker):]
}

// pendingPartialUploadBase returns the pending object name that a partial
// upload belongs to. On backends with partial uploads (local disks and SFTP,
// for example) rclone writes an upload to "<name>.<8 hex digits>.partial" and
// renames it to <name> only once the upload is complete. The file stays behind
// when rclone can't run its own cleanup: a hard kill (TerminateJobObject on
// Windows, SIGKILL after the grace period elsewhere), a crash, or a lost
// connection. On Unix the normal cancel sends SIGTERM first, and rclone then
// removes the partial itself. A partial is never a committed object, so
// password-change cleanup deletes it without reading it. Any other unexpected
// name still fails the password change.
func pendingPartialUploadBase(name string) (string, bool) {
	trimmed, found := strings.CutSuffix(name, ".partial")
	if !found || len(trimmed) < 9 || trimmed[len(trimmed)-9] != '.' {
		return "", false
	}
	for _, digit := range trimmed[len(trimmed)-8:] {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return "", false
		}
	}
	base := trimmed[:len(trimmed)-9]
	return base, validPendingRotationName(base)
}

// CapturePasswordRotationInventory decrypts only the bounded protected root,
// authoritative profiles and their retained fallbacks. It never enumerates or
// stages native repository payload.
func (s Store) CapturePasswordRotationInventory(ctx context.Context, operationUUID string, requireFence bool) (inventory PasswordRotationInventory, err error) {
	if !exactUUID(operationUUID) {
		return inventory, fmt.Errorf("password-change operation UUID is invalid")
	}
	session, err := s.session(ctx)
	if err != nil {
		return inventory, err
	}
	defer finishStoreSession(ctx, session, &err)
	objects, err := profileObjects(ctx, session)
	if err != nil {
		return inventory, err
	}
	protected := make([]string, 0, len(objects))
	profiles := map[string]bool{}
	for name := range objects {
		if strings.Contains(name, ".pending.") {
			if _, partial := pendingPartialUploadBase(name); !partial && !validPendingRotationName(name) {
				return inventory, fmt.Errorf("protected metadata contains an invalid pending object")
			}
			inventory.Pending = append(inventory.Pending, name)
			continue
		}
		if name != canonicalRootObject && name != previousRootObject &&
			!strings.HasSuffix(name, "/profile.replicaro") && !strings.HasSuffix(name, "/profile.replicaro.previous") {
			continue
		}
		protected = append(protected, name)
		if strings.HasPrefix(name, "profiles/") {
			profiles[strings.Split(name, "/")[1]] = true
		}
	}
	if len(profiles) == 0 || len(profiles) > MaximumPasswordChangeProfiles {
		return inventory, fmt.Errorf("vault password change requires 1 to %d authoritative profiles", MaximumPasswordChangeProfiles)
	}
	if _, exists := objects[canonicalRootObject]; !exists {
		return inventory, fmt.Errorf("canonical protected vault root is required")
	}
	for profileUUID := range profiles {
		if _, exists := objects["profiles/"+profileUUID+"/profile.replicaro"]; !exists {
			return inventory, fmt.Errorf("canonical protected profile %s is required", profileUUID)
		}
	}
	sort.Strings(protected)
	sort.Strings(inventory.Pending)
	inventory.Version, inventory.RepositoryID, inventory.OperationUUID = 1, s.Repository.ID, operationUUID
	var cumulativeSize int64
	for _, name := range protected {
		scoped, scopeErr := rotationStoreForObject(s, name)
		if scopeErr != nil {
			return inventory, scopeErr
		}
		data, readErr := scoped.readObject(ctx, session, name, objects[name])
		if readErr != nil {
			return inventory, fmt.Errorf("read protected password-change object %s: %w", name, readErr)
		}
		if strings.HasSuffix(name, "profile.replicaro") {
			profile, parseErr := Parse(data)
			if parseErr != nil || (requireFence && profile.PasswordChange == nil) ||
				(profile.PasswordChange != nil && profile.PasswordChange.OperationUUID != operationUUID) {
				return inventory, fmt.Errorf("profile password-change fence is missing or mismatched")
			}
		}
		if name == canonicalRootObject {
			root, parseErr := ParseRoot(data, s.Repository.Connector)
			if parseErr != nil || (requireFence && root.PasswordChange == nil) ||
				(root.PasswordChange != nil && root.PasswordChange.OperationUUID != operationUUID) {
				return inventory, fmt.Errorf("root password-change fence is missing or mismatched")
			}
		}
		digest := sha256.Sum256(data)
		// Check before addition so the accepted complete-inventory bound cannot
		// be bypassed by integer overflow.
		if int64(len(data)) > MaximumPasswordRotationBytes-cumulativeSize {
			return inventory, fmt.Errorf("protected password-change metadata exceeds the cumulative limit")
		}
		cumulativeSize += int64(len(data))
		inventory.Objects = append(inventory.Objects, PasswordRotationObject{
			Name: name, Role: rotationRole(name), Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), Data: data,
		})
	}
	return inventory, nil
}

func inventoryEqual(left, right PasswordRotationInventory) bool {
	if len(left.Objects) != len(right.Objects) || len(left.Pending) != len(right.Pending) {
		return false
	}
	for index := range left.Objects {
		if left.Objects[index].Name != right.Objects[index].Name || left.Objects[index].Size != right.Objects[index].Size || left.Objects[index].SHA256 != right.Objects[index].SHA256 {
			return false
		}
	}
	for index := range left.Pending {
		if left.Pending[index] != right.Pending[index] {
			return false
		}
	}
	return true
}

func PasswordRotationInventoriesEqual(left, right PasswordRotationInventory) bool {
	return inventoryEqual(left, right)
}

func derivedPendingName(target, operationUUID string) (string, error) {
	namespace, err := uuid.Parse(operationUUID)
	if err != nil {
		return "", err
	}
	derived := uuid.NewSHA1(namespace, []byte(target)).String()
	base := strings.TrimSuffix(target, ".previous")
	return base + ".pending." + derived, nil
}

func (s Store) writePasswordRotationObject(ctx context.Context, session *storeSession, target string, plaintext []byte, operationUUID, expectedDigest string, requireExpected bool) (err error) {
	scoped, err := rotationStoreForObject(s, target)
	if err != nil {
		return err
	}
	if err := scoped.validateRecord(plaintext); err != nil {
		return err
	}
	if requireExpected {
		objects, listErr := profileObjects(ctx, session)
		if listErr != nil {
			return listErr
		}
		stat, exists := objects[target]
		if !exists {
			return fmt.Errorf("protected object %s changed before password publication", target)
		}
		current, readErr := scoped.readObject(ctx, session, target, stat)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(current)
		if hex.EncodeToString(digest[:]) != expectedDigest {
			return fmt.Errorf("protected object %s changed before password publication", target)
		}
	}
	pending, err := derivedPendingName(target, operationUUID)
	if err != nil {
		return err
	}
	localPath, err := passwordRotationUploadPath(s.Repository.ID, operationUUID, target)
	if err != nil {
		return err
	}
	if removeErr := removePasswordRotationFile(localPath); removeErr != nil {
		return removeErr
	}
	file, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(plaintext); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	// Best-effort removal here reduces plaintext lifetime, but the derived
	// operation stage remains the authoritative cleanup inventory. A removal
	// failure must not turn a completed remote publication into false failure;
	// final stage cleanup will retain cleanup_pending until the file is gone.
	defer func() { _ = removePasswordRotationFile(localPath) }()
	if _, err := session.run(ctx, "copyto", localPath, sidecarRemote+pending, "--ignore-times"); err != nil {
		return fmt.Errorf("upload password-change pending object: %w", err)
	}
	verified, err := scoped.readObjectBounded(ctx, session, pending)
	if err != nil || string(verified) != string(plaintext) {
		return fmt.Errorf("verify password-change pending object")
	}
	if requireExpected {
		objects, listErr := profileObjects(ctx, session)
		if listErr != nil {
			return listErr
		}
		stat, exists := objects[target]
		if !exists {
			return fmt.Errorf("protected object %s changed before password publication", target)
		}
		current, readErr := scoped.readObject(ctx, session, target, stat)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(current)
		if hex.EncodeToString(digest[:]) != expectedDigest {
			return fmt.Errorf("protected object %s changed before password publication", target)
		}
	}
	if _, err := session.run(ctx, "copyto", sidecarRemote+pending, sidecarRemote+target, "--ignore-times"); err != nil {
		return err
	}
	verified, err = scoped.readObjectBounded(ctx, session, target)
	if err != nil || string(verified) != string(plaintext) {
		return fmt.Errorf("verify password-change published object")
	}
	cleanupProfileObject(ctx, session, pending)
	return nil
}

func fencedPlaintext(s Store, object PasswordRotationObject, operationUUID string, add bool) ([]byte, error) {
	now := time.Now().UTC()
	if object.Role == "root_canonical" {
		root, err := ParseRoot(object.Data, s.Repository.Connector)
		if err != nil {
			return nil, err
		}
		if add {
			if root.PasswordChange != nil && root.PasswordChange.OperationUUID != operationUUID {
				return nil, fmt.Errorf("another vault-password change fence exists")
			}
			if root.PasswordChange != nil {
				return append([]byte(nil), object.Data...), nil
			}
			root.PasswordChange = &PasswordChange{OperationUUID: operationUUID}
		} else {
			if root.PasswordChange == nil {
				return append([]byte(nil), object.Data...), nil
			}
			if root.PasswordChange.OperationUUID != operationUUID {
				return nil, fmt.Errorf("vault-password change fence changed")
			}
			root.PasswordChange = nil
		}
		root.Revision++
		root.UpdatedAt = now
		return MarshalRoot(root, s.Repository.Connector)
	}
	profile, err := Parse(object.Data)
	if err != nil {
		return nil, err
	}
	if add {
		if profile.PasswordChange != nil && profile.PasswordChange.OperationUUID != operationUUID {
			return nil, fmt.Errorf("another profile password-change fence exists")
		}
		if profile.PasswordChange != nil {
			return append([]byte(nil), object.Data...), nil
		}
		profile.PasswordChange = &PasswordChange{OperationUUID: operationUUID}
	} else {
		if profile.PasswordChange == nil {
			return append([]byte(nil), object.Data...), nil
		}
		if profile.PasswordChange.OperationUUID != operationUUID {
			return nil, fmt.Errorf("profile password-change fence changed")
		}
		profile.PasswordChange = nil
	}
	profile.Revision++
	profile.UpdatedAt = now
	return Marshal(profile)
}

func (s Store) SetPasswordChangeFence(ctx context.Context, inventory PasswordRotationInventory, add bool) (err error) {
	session, err := s.session(ctx)
	if err != nil {
		return err
	}
	defer finishStoreSession(ctx, session, &err)
	objects := append([]PasswordRotationObject(nil), inventory.Objects...)
	sort.SliceStable(objects, func(i, j int) bool {
		if add {
			leftRoot, rightRoot := objects[i].Role == "root_canonical", objects[j].Role == "root_canonical"
			if leftRoot != rightRoot {
				return leftRoot
			}
			return objects[i].Name < objects[j].Name
		}
		if objects[i].Role == "root_canonical" {
			return false
		}
		if objects[j].Role == "root_canonical" {
			return true
		}
		return objects[i].Name < objects[j].Name
	})
	for _, object := range objects {
		if object.Role != "root_canonical" && object.Role != "profile_canonical" {
			continue
		}
		plaintext, transformErr := fencedPlaintext(s, object, inventory.OperationUUID, add)
		if transformErr != nil {
			return transformErr
		}
		if string(plaintext) != string(object.Data) {
			if err := s.writePasswordRotationObject(ctx, session, object.Name, plaintext, inventory.OperationUUID, object.SHA256, true); err != nil {
				return err
			}
		}
		if add && object.Role == "root_canonical" {
			if err := passwordRotationFault("root_fence_published"); err != nil {
				return err
			}
		}
		if add && object.Role == "profile_canonical" {
			if err := passwordRotationFault("profile_fence_published"); err != nil {
				return err
			}
		}
	}
	if add {
		if err := passwordRotationFault("profile_fences_published"); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) DeletePasswordChangePending(ctx context.Context, inventory PasswordRotationInventory) (err error) {
	return s.deletePasswordChangePending(ctx, inventory, false)
}

// DeletePasswordChangeOperationPending is rollback-only cleanup. It removes
// only pending names deterministically derived from this operation and the
// exact protected objects in its freshly observed inventory.
func (s Store) DeletePasswordChangeOperationPending(ctx context.Context, inventory PasswordRotationInventory) (err error) {
	return s.deletePasswordChangePending(ctx, inventory, true)
}

func (s Store) deletePasswordChangePending(ctx context.Context, inventory PasswordRotationInventory, exactOperationOnly bool) (err error) {
	if len(inventory.Pending) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	if exactOperationOnly {
		for _, object := range inventory.Objects {
			name, deriveErr := derivedPendingName(object.Name, inventory.OperationUUID)
			if deriveErr != nil {
				return deriveErr
			}
			allowed[name] = true
		}
	}
	session, err := s.session(ctx)
	if err != nil {
		return err
	}
	defer finishStoreSession(ctx, session, &err)
	for _, name := range inventory.Pending {
		// A partial upload holds incomplete ciphertext, so it is removed
		// without the read-back below. Rollback removes the partial uploads
		// of its own pending names as well.
		pendingName, partial := pendingPartialUploadBase(name)
		if !partial {
			pendingName = name
		}
		if exactOperationOnly && !allowed[pendingName] {
			continue
		}
		if !validPendingRotationName(pendingName) {
			return fmt.Errorf("invalid pending protected object")
		}
		before, exists, statErr := statObject(ctx, session, sidecarRemote+name)
		if statErr != nil {
			return statErr
		}
		if !exists {
			continue
		}
		if !partial {
			scoped, scopeErr := rotationStoreForObject(s, name)
			if scopeErr != nil {
				return scopeErr
			}
			beforeData, readErr := scoped.readObject(ctx, session, name, before)
			if readErr != nil {
				if !pendingObjectContentInvalid(before, readErr) {
					return fmt.Errorf("revalidate pending protected object before cleanup: %w", readErr)
				}
				// Rollback only reaches names derived from its own operation
				// UUID, which no other computer writes, so a damaged one is
				// this change's own cut-off upload and goes at once. Waiting
				// would hold a resumed rollback back for half an hour behind
				// a busy error that blames another computer.
				if !exactOperationOnly {
					if err := requireAbandonedPendingObject(before, time.Now()); err != nil {
						return err
					}
				}
			} else {
				after, exists, statErr := statObject(ctx, session, sidecarRemote+name)
				if statErr != nil || !exists || before.Size != after.Size || before.Path != after.Path {
					return fmt.Errorf("pending protected object changed before cleanup")
				}
				afterData, readErr := scoped.readObject(ctx, session, name, after)
				if readErr != nil || !bytesEqual(beforeData, afterData) {
					return fmt.Errorf("pending protected object changed before cleanup")
				}
			}
		}
		if _, err := session.run(ctx, "deletefile", sidecarRemote+name); err != nil {
			return err
		}
		if _, exists, err := statObject(ctx, session, sidecarRemote+name); err != nil || exists {
			return fmt.Errorf("verify pending protected-object cleanup")
		}
	}
	return passwordRotationFault("pending_cleanup_completed")
}

// ErrPasswordChangeVaultBusy refuses a password change while a pending
// object it can't read was written too recently to be a leftover.
var ErrPasswordChangeVaultBusy = errors.New("Another computer may be changing this vault right now. Try again in a few minutes.")

// abandonedPendingObjectAge is how long a pending object whose contents fail
// their check must stay unchanged before password-change cleanup treats it as
// a leftover.
const abandonedPendingObjectAge = 30 * time.Minute

// pendingObjectContentInvalid reports whether a pending object's contents
// fail rclone crypt's own check. Pending names carry no checksum (the suffix
// is a UUID derived from the operation), so the check is the one crypt keeps
// with every block: a truncated or otherwise damaged object fails its
// authentication, and one too short to hold crypt's header lists with no
// plaintext size at all. Some WebDAV servers leave such an object under the
// real pending name, instead of a .partial, when an upload is cut off. An
// object another computer wrote under a different vault password fails the
// same check, which is why shared cleanup deletes only an old one (see
// requireAbandonedPendingObject); rollback deletes its own names at once. Any
// other read failure, such as a network error, still stops the password
// change.
func pendingObjectContentInvalid(stat objectStat, readErr error) bool {
	if hasStorePostCommandFailure(readErr) {
		return false
	}
	return stat.Size <= 0 || errors.Is(readErr, errSavedVaultPasswordDecrypt)
}

// requireAbandonedPendingObject lets cleanup delete a pending object whose
// contents fail their check only when it hasn't changed for
// abandonedPendingObjectAge, by the modification time rclone lists for it,
// which on most backends is the uploading computer's clock at upload. A newer
// one may be another computer's upload in progress, so the password change is
// refused with ErrPasswordChangeVaultBusy and nothing is deleted. There's no
// second look just before the delete: it would come about a second later,
// and a server that caches listings wouldn't show a change by then anyway.
func requireAbandonedPendingObject(before objectStat, now time.Time) error {
	modified, err := time.Parse(time.RFC3339Nano, before.ModTime)
	if err != nil || now.Sub(modified) < abandonedPendingObjectAge {
		return ErrPasswordChangeVaultBusy
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func PasswordRotationStagePath(repositoryID, operationUUID string) (string, error) {
	if !exactUUID(repositoryID) || !exactUUID(operationUUID) {
		return "", fmt.Errorf("password-change staging identity is invalid")
	}
	root, err := appdata.PasswordRotationRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, repositoryID, operationUUID), nil
}

// PreparePasswordRotationStage creates password-change/<repository>/<operation>
// owner-only, reusing any of those folders that already exist.
//
// Staging trusts the folders it creates under the app-data root. Links above
// or in these folders are treated like ordinary paths; member removal uses
// os.Remove, which removes a link without following it. Some users' app-data
// root sits under a linked folder (a symlinked home or ~/.local, folders placed
// by a dotfile manager, /home -> /var/home on ostree systems), and a link
// planted inside our owner-only folders takes someone or something already on
// the computer, which is outside what Replicaro defends against. So there is
// no walk from the filesystem root and no link, owner, mode, or link-count
// re-check on what was just created. What protects staged plaintext against
// accidents is that folders are 0700 and files 0600 with O_EXCL, every write
// is fsynced, reads are bounded, and cleanup only ever removes the stage's
// fixed member names. Don't add link or owner checks here without a product
// decision: they turn ordinary home-folder layouts into failed password
// changes.
func PreparePasswordRotationStage(repositoryID, operationUUID string) (string, error) {
	path, err := PasswordRotationStagePath(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	root := filepath.Dir(filepath.Dir(path))
	for _, directory := range []string{root, filepath.Dir(path), path} {
		created, err := preparePasswordRotationDirectory(directory)
		if err != nil {
			return "", err
		}
		if created {
			if err := syncPasswordRotationDirectory(filepath.Dir(directory)); err != nil {
				return "", err
			}
		}
	}
	return path, nil
}

// preparePasswordRotationDirectory creates one stage folder owner-only, or
// accepts the folder that is already there, and in both cases sets mode 0700
// again. On Windows the folder inherits the application folder's protected
// DACL instead and gets no ACL write here. It reports whether it created the
// folder so the caller can fsync the parent.
func preparePasswordRotationDirectory(path string) (bool, error) {
	created := true
	if err := os.Mkdir(path, 0o700); errors.Is(err, os.ErrExist) {
		created = false
		info, statErr := os.Stat(path)
		if statErr != nil {
			return false, statErr
		}
		if !info.IsDir() {
			return false, fmt.Errorf("password-change staging component is not a directory")
		}
	} else if err != nil {
		return false, err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return false, err
	}
	return created, nil
}

// validatePasswordRotationStage returns the derived stage folder for this
// operation once it exists. Callers never accept a stored path; the UUIDs are
// the only input.
func validatePasswordRotationStage(repositoryID, operationUUID string) (string, error) {
	path, err := PasswordRotationStagePath(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("password-change staging path is not a directory")
	}
	return path, nil
}

func passwordRotationUploadPath(repositoryID, operationUUID, target string) (string, error) {
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(target))
	return filepath.Join(path, "upload-"+hex.EncodeToString(digest[:])+".json"), nil
}

func PasswordRotationNativeInputPath(repositoryID, operationUUID string) (string, error) {
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "restic-new-password.txt"), nil
}

func WritePasswordRotationNativeInput(repositoryID, operationUUID, password string) (string, error) {
	if err := models.ValidateVaultPassword(password); err != nil {
		return "", err
	}
	path, err := PasswordRotationNativeInputPath(repositoryID, operationUUID)
	if err != nil {
		return "", err
	}
	if err := removePasswordRotationFile(path); err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, writeErr := file.WriteString(password + "\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return "", err
	}
	if err := syncPasswordRotationDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return path, nil
}

func StagePasswordRotationInventory(repositoryID, operationUUID string, inventory PasswordRotationInventory) error {
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return err
	}
	if inventory.RepositoryID != repositoryID || inventory.OperationUUID != operationUUID {
		return fmt.Errorf("password-change staging identity is invalid")
	}
	var total int64
	for _, object := range inventory.Objects {
		total += object.Size
	}
	if total < 0 || total > MaximumPasswordRotationBytes {
		return fmt.Errorf("protected password-change metadata exceeds the cumulative limit")
	}
	if available, err := passwordRotationAvailableBytes(path); err == nil && available < uint64(total) {
		return fmt.Errorf("insufficient local space for password-change staging")
	}
	for index := range inventory.Objects {
		name := fmt.Sprintf("object-%03d.json", index)
		file, err := os.OpenFile(filepath.Join(path, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(inventory.Objects[index].Data)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.Join(writeErr, closeErr)
		}
		if err := os.Chmod(filepath.Join(path, name), 0o600); err != nil {
			return err
		}
		inventory.Objects[index].StagedFile = name
		inventory.Objects[index].Data = nil
		if err := passwordRotationFault("staged_object_durable"); err != nil {
			return err
		}
	}
	manifest, err := json.MarshalIndent(inventory, "", "  ")
	if err != nil {
		return err
	}
	manifest = append(manifest, '\n')
	file, err := os.OpenFile(filepath.Join(path, "manifest.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(manifest)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(writeErr, closeErr)
	}
	if err := os.Chmod(filepath.Join(path, "manifest.json"), 0o600); err != nil {
		return err
	}
	if err := syncPasswordRotationDirectory(path); err != nil {
		return err
	}
	return passwordRotationFault("staged_manifest_durable")
}

func ResetPasswordRotationStage(repositoryID, operationUUID string) error {
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !validPasswordRotationStageFilename(name) {
			return fmt.Errorf("password-change staging contains an unexpected object")
		}
		if err := os.Remove(filepath.Join(path, name)); err != nil {
			return err
		}
	}
	return syncPasswordRotationDirectory(path)
}

func LoadPasswordRotationInventory(repositoryID, operationUUID string) (PasswordRotationInventory, error) {
	var inventory PasswordRotationInventory
	path, err := validatePasswordRotationStage(repositoryID, operationUUID)
	if err != nil {
		return inventory, err
	}
	data, err := readPasswordRotationFileBounded(filepath.Join(path, "manifest.json"), maximumPasswordRotationManifestBytes)
	if err != nil {
		return inventory, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil || inventory.Version != 1 || inventory.RepositoryID != repositoryID || inventory.OperationUUID != operationUUID {
		return PasswordRotationInventory{}, fmt.Errorf("password-change staging manifest is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PasswordRotationInventory{}, fmt.Errorf("password-change staging manifest has trailing content")
	}
	if len(inventory.Objects) == 0 || len(inventory.Objects) > 2+2*MaximumPasswordChangeProfiles {
		return PasswordRotationInventory{}, fmt.Errorf("password-change staging object count is invalid")
	}
	if len(inventory.Pending) != 0 {
		return PasswordRotationInventory{}, fmt.Errorf("password-change staging contains a pending remote object")
	}
	seenNames := map[string]bool{}
	profiles := map[string]bool{}
	previousProfiles := map[string]bool{}
	rootCanonical, rootPrevious := 0, 0
	lastName := ""
	for _, object := range inventory.Objects {
		limit := int64(MaximumProfileDecryptedSize)
		if object.Role == "root_canonical" || object.Role == "root_previous" {
			limit = MaximumRootDecryptedSize
		}
		if !validRotationObjectName(object.Name) || seenNames[object.Name] || (lastName != "" && object.Name <= lastName) || object.Role != rotationRole(object.Name) ||
			object.Size <= 0 || object.Size > limit || len(object.SHA256) != sha256.Size*2 {
			return PasswordRotationInventory{}, fmt.Errorf("password-change staging object identity is invalid")
		}
		if _, err := hex.DecodeString(object.SHA256); err != nil {
			return PasswordRotationInventory{}, fmt.Errorf("password-change staging object digest is invalid")
		}
		seenNames[object.Name] = true
		lastName = object.Name
		switch object.Role {
		case "root_canonical":
			rootCanonical++
		case "root_previous":
			rootPrevious++
		case "profile_canonical":
			profiles[strings.Split(object.Name, "/")[1]] = true
		case "profile_previous":
			previousProfiles[strings.Split(object.Name, "/")[1]] = true
		default:
			return PasswordRotationInventory{}, fmt.Errorf("password-change staging object role is invalid")
		}
	}
	if rootCanonical != 1 || rootPrevious > 1 || len(profiles) == 0 || len(profiles) > MaximumPasswordChangeProfiles {
		return PasswordRotationInventory{}, fmt.Errorf("password-change staging membership is invalid")
	}
	for profileUUID := range previousProfiles {
		if !profiles[profileUUID] {
			return PasswordRotationInventory{}, fmt.Errorf("password-change staging fallback has no canonical profile")
		}
	}
	var cumulativeSize int64
	for index := range inventory.Objects {
		name := inventory.Objects[index].StagedFile
		if name != fmt.Sprintf("object-%03d.json", index) {
			return PasswordRotationInventory{}, fmt.Errorf("password-change staging path is invalid")
		}
		objectPath := filepath.Join(path, name)
		limit := int64(MaximumProfileDecryptedSize)
		if inventory.Objects[index].Role == "root_canonical" || inventory.Objects[index].Role == "root_previous" {
			limit = MaximumRootDecryptedSize
		}
		objectData, err := readPasswordRotationFileBounded(objectPath, limit)
		if err != nil {
			return PasswordRotationInventory{}, err
		}
		digest := sha256.Sum256(objectData)
		if int64(len(objectData)) != inventory.Objects[index].Size || hex.EncodeToString(digest[:]) != inventory.Objects[index].SHA256 {
			return PasswordRotationInventory{}, fmt.Errorf("password-change staged object verification failed")
		}
		if int64(len(objectData)) > MaximumPasswordRotationBytes-cumulativeSize {
			return PasswordRotationInventory{}, fmt.Errorf("protected password-change metadata exceeds the cumulative limit")
		}
		cumulativeSize += int64(len(objectData))
		inventory.Objects[index].Data = objectData
	}
	return inventory, nil
}

func stripPasswordFence(s Store, object PasswordRotationObject, operationUUID string) ([]byte, error) {
	if object.Role == "root_canonical" {
		root, err := ParseRoot(object.Data, s.Repository.Connector)
		if err != nil {
			return nil, err
		}
		if root.PasswordChange == nil || root.PasswordChange.OperationUUID != operationUUID {
			return nil, fmt.Errorf("staged root password fence is invalid")
		}
		root.PasswordChange = nil
		root.Revision++
		root.UpdatedAt = root.UpdatedAt.Add(time.Nanosecond)
		return MarshalRoot(root, s.Repository.Connector)
	}
	if object.Role == "profile_canonical" {
		profile, err := Parse(object.Data)
		if err != nil {
			return nil, err
		}
		if profile.PasswordChange == nil || profile.PasswordChange.OperationUUID != operationUUID {
			return nil, fmt.Errorf("staged profile password fence is invalid")
		}
		profile.PasswordChange = nil
		profile.Revision++
		profile.UpdatedAt = profile.UpdatedAt.Add(time.Nanosecond)
		return Marshal(profile)
	}
	return append([]byte(nil), object.Data...), nil
}

// removeOwnPasswordRotationPartialUploads deletes, without reading them, the
// rclone partial uploads of this operation's own pending names. An earlier
// publishing attempt that was cut off mid-upload leaves one behind, and a
// resume can't overwrite it: the partial's hex suffix comes from the local
// upload file, which every attempt writes anew, so rclone picks a different
// partial name and never touches the old one. Without this the check below
// would refuse every resume of the operation. The pending names are derived
// from this operation's UUID, so no other writer uses them. Any other pending
// object or partial upload is left alone and still fails the check.
func removeOwnPasswordRotationPartialUploads(ctx context.Context, session *storeSession, inventory PasswordRotationInventory) error {
	own := make(map[string]bool, len(inventory.Objects))
	for _, object := range inventory.Objects {
		name, err := derivedPendingName(object.Name, inventory.OperationUUID)
		if err != nil {
			return err
		}
		own[name] = true
	}
	listed, err := profileObjects(ctx, session)
	if err != nil {
		return err
	}
	for name := range listed {
		pendingName, partial := pendingPartialUploadBase(name)
		if !partial || !own[pendingName] {
			continue
		}
		if _, err := session.run(ctx, "deletefile", sidecarRemote+name); err != nil {
			return err
		}
		if _, exists, err := statObject(ctx, session, sidecarRemote+name); err != nil || exists {
			return fmt.Errorf("verify password-change partial upload cleanup")
		}
	}
	return nil
}

func (s Store) verifyPasswordRotatedObjectsBeforeRoot(ctx context.Context, session *storeSession, inventory PasswordRotationInventory) error {
	listed, err := profileObjects(ctx, session)
	if err != nil {
		return err
	}
	expected := make(map[string]PasswordRotationObject, len(inventory.Objects))
	for _, object := range inventory.Objects {
		expected[object.Name] = object
	}
	for name := range listed {
		if strings.Contains(name, ".pending.") {
			return fmt.Errorf("new-password protected tree still contains a pending object")
		}
		if _, ok := expected[name]; !ok {
			return fmt.Errorf("new-password protected tree membership changed")
		}
	}
	if len(listed) != len(expected) {
		return fmt.Errorf("new-password protected tree membership is incomplete")
	}
	for _, object := range inventory.Objects {
		if object.Role == "root_canonical" {
			// The old-password fenced canonical root intentionally remains in
			// place until this complete pre-commit verification succeeds.
			continue
		}
		scoped, err := rotationStoreForObject(s, object.Name)
		if err != nil {
			return err
		}
		plaintext, err := scoped.readObject(ctx, session, object.Name, listed[object.Name])
		if err != nil {
			return fmt.Errorf("verify new-password protected object %s: %w", object.Name, err)
		}
		expectedPlaintext, err := stripPasswordFence(s, object, inventory.OperationUUID)
		if err != nil || !bytesEqual(plaintext, expectedPlaintext) {
			return fmt.Errorf("new-password protected object %s differs before root commit", object.Name)
		}
	}
	return nil
}

func (s Store) PublishPasswordRotatedTree(ctx context.Context, inventory PasswordRotationInventory) (err error) {
	session, err := s.session(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if session != nil {
			finishStoreSession(ctx, session, &err)
		}
	}()
	objects := append([]PasswordRotationObject(nil), inventory.Objects...)
	sort.SliceStable(objects, func(i, j int) bool {
		order := func(role string) int {
			switch role {
			case "profile_previous":
				return 0
			case "profile_canonical":
				return 1
			case "root_previous":
				return 2
			default:
				return 3
			}
		}
		left, right := order(objects[i].Role), order(objects[j].Role)
		if left != right {
			return left < right
		}
		return objects[i].Name < objects[j].Name
	})
	var rootCanonical *PasswordRotationObject
	for index := range objects {
		object := objects[index]
		if object.Role == "root_canonical" {
			rootCanonical = &objects[index]
			continue
		}
		plaintext, transformErr := stripPasswordFence(s, object, inventory.OperationUUID)
		if transformErr != nil {
			return transformErr
		}
		if err := s.writePasswordRotationObject(ctx, session, object.Name, plaintext, inventory.OperationUUID, "", false); err != nil {
			return err
		}
		switch object.Role {
		case "profile_canonical":
			if err := passwordRotationFault("profile_published"); err != nil {
				return err
			}
		case "profile_previous", "root_previous":
			if err := passwordRotationFault("fallback_published"); err != nil {
				return err
			}
		}
	}
	if rootCanonical == nil {
		return fmt.Errorf("password-change staging has no canonical root")
	}
	if err := removeOwnPasswordRotationPartialUploads(ctx, session, inventory); err != nil {
		return err
	}
	if err := s.verifyPasswordRotatedObjectsBeforeRoot(ctx, session, inventory); err != nil {
		return err
	}
	rootPlaintext, err := stripPasswordFence(s, *rootCanonical, inventory.OperationUUID)
	if err != nil {
		return err
	}
	if err := s.writePasswordRotationObject(ctx, session, rootCanonical.Name, rootPlaintext, inventory.OperationUUID, "", false); err != nil {
		return err
	}
	if err := passwordRotationFault("root_published"); err != nil {
		return err
	}
	finishStoreSession(ctx, session, &err)
	session = nil
	if err != nil {
		return err
	}
	final, err := s.CapturePasswordRotationInventory(ctx, inventory.OperationUUID, false)
	if err != nil {
		return err
	}
	if len(final.Pending) != 0 || len(final.Objects) != len(inventory.Objects) {
		return fmt.Errorf("new-password protected tree verification is incomplete")
	}
	for index := range final.Objects {
		expected, transformErr := stripPasswordFence(s, inventory.Objects[index], inventory.OperationUUID)
		if transformErr != nil {
			return transformErr
		}
		digest := sha256.Sum256(expected)
		if final.Objects[index].Name != inventory.Objects[index].Name || final.Objects[index].SHA256 != hex.EncodeToString(digest[:]) {
			return fmt.Errorf("new-password protected tree verification differs")
		}
	}
	return nil
}

func CleanupPasswordRotationStage(repositoryID, operationUUID string) error {
	return cleanupPasswordRotationStage(repositoryID, operationUUID, false)
}

func cleanupPasswordRotationStage(repositoryID, operationUUID string, keepRecord bool) error {
	path, err := PasswordRotationStagePath(repositoryID, operationUUID)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	// The durable database operation plus the exact derived directory preserve
	// cleanup identity even if an earlier attempt removed some files or the
	// manifest. Only fixed rotation members are ever eligible for removal. Any
	// other name stops cleanup before the manifest and the folder go, so the
	// operation stays retryable instead of deleting a folder that holds
	// something we didn't put there. Each member goes through os.Remove, which
	// deletes a link itself rather than what it points to and never recurses,
	// so no per-file type or link check is needed first.
	for _, entry := range entries {
		if !validPasswordRotationStageFilename(entry.Name()) {
			return fmt.Errorf("password-change staging contains an unexpected object")
		}
		filePath := filepath.Join(path, entry.Name())
		if entry.Name() == "manifest.json" || (keepRecord && entry.Name() == passwordRotationRecordName) {
			continue
		}
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := syncPasswordRotationDirectory(path); err != nil {
		return err
	}
	manifest := filepath.Join(path, "manifest.json")
	if err := os.Remove(manifest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncPasswordRotationDirectory(path); err != nil {
		return err
	}
	if keepRecord {
		return nil
	}
	parent := filepath.Dir(path)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncPasswordRotationDirectory(parent); err != nil {
		return err
	}
	return passwordRotationFault("local_cleanup_deleted")
}

func validPasswordRotationStageFilename(name string) bool {
	switch name {
	case "manifest.json", "restic-new-password.txt",
		passwordRotationRecordName, passwordRotationRecordTempName, passwordRotationFenceName:
		return true
	}
	if strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && len(name) == len("object-000.json") {
		for _, value := range name[len("object-") : len("object-")+3] {
			if value < '0' || value > '9' {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(name, "upload-") && strings.HasSuffix(name, ".json") {
		digest := strings.TrimSuffix(strings.TrimPrefix(name, "upload-"), ".json")
		decoded, err := hex.DecodeString(digest)
		return err == nil && len(decoded) == sha256.Size && digest == strings.ToLower(digest)
	}
	return false
}

// removePasswordRotationFile removes one fixed-name stage member. os.Remove
// deletes a link rather than its target and never recurses.
func removePasswordRotationFile(path string) error {
	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return syncPasswordRotationDirectory(filepath.Dir(path))
}

// readPasswordRotationFileBounded reads one staged file and refuses anything
// over limit before allocating for it.
func readPasswordRotationFileBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() < 0 || info.Size() > limit {
		_ = file.Close()
		return nil, fmt.Errorf("password-change staging file exceeds its size limit")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("password-change staging file exceeds its size limit")
	}
	return data, nil
}
