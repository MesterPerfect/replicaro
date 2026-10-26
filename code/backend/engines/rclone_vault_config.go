package engines

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/local/replicaro/appdata"
	"github.com/local/replicaro/command"
	"github.com/local/replicaro/models"
)

var runRcloneVaultConfigCommand = command.RunWithInputSecretsPrivateOutput

const maximumRcloneVaultConfigBytes = 8 << 20

// RcloneVaultConfigBinding selects one ordinary canonical private config path.
// Revalidate checks that path again; nothing is kept open across a native
// command, because rclone replaces the file when it saves a refreshed token.
type RcloneVaultConfigBinding struct {
	path       string
	revalidate func(context.Context) error
}

func (binding *RcloneVaultConfigBinding) Path() string {
	if binding == nil {
		return ""
	}
	return binding.path
}

func (binding *RcloneVaultConfigBinding) NativePath() string {
	return binding.Path()
}

func (binding *RcloneVaultConfigBinding) Close() error {
	return nil
}

func (binding *RcloneVaultConfigBinding) Revalidate(ctx context.Context) error {
	if binding == nil || binding.revalidate == nil {
		return nil
	}
	return binding.revalidate(ctx)
}

func SetRcloneVaultConfigRunnerForTests(next func(
	context.Context, string, []string, []string, string, time.Duration, string,
) (string, error)) func() {
	previous := runRcloneVaultConfigCommand
	runRcloneVaultConfigCommand = next
	return func() {
		runRcloneVaultConfigCommand = previous
	}
}

func validRepositoryUUID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}

// RcloneVaultConfigPath resolves the only durable config path for a repository.
func RcloneVaultConfigPath(repositoryID string) (string, error) {
	if !validRepositoryUUID(repositoryID) {
		return "", fmt.Errorf("rclone vault repository ID must be a canonical UUID")
	}
	root, err := appdata.RcloneVaultConfigRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, repositoryID, "rclone.conf"), nil
}

func rcloneConfigPathForRepository(repo models.Repository) (string, error) {
	if repo.RcloneConfigPath != "" {
		absolute, err := filepath.Abs(repo.RcloneConfigPath)
		if err != nil {
			return "", err
		}
		if absolute != filepath.Clean(repo.RcloneConfigPath) {
			return "", invalidRcloneLocalBinding(fmt.Errorf("staged rclone config path is not canonical"))
		}
		return absolute, nil
	}
	return RcloneVaultConfigPath(repo.ID)
}

func localRcloneBindingFailure(message string, err error) error {
	result := fmt.Errorf("%s: %w", message, err)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errInvalidRcloneLocalBinding) {
		return reconnectRequired(result)
	}
	return result
}

func privateRcloneOperationDirectories() (root, cache, temporary string, cleanup func() error, err error) {
	parent, err := appdata.RcloneSessionRoot()
	if err != nil {
		return "", "", "", nil, err
	}
	if err := makePrivateRcloneDirectory(parent); err != nil {
		return "", "", "", nil, err
	}
	root, err = os.MkdirTemp(parent, "op-")
	if err != nil {
		return "", "", "", nil, err
	}
	cleanup = func() error { return removeRcloneSession(root) }
	cache, temporary = filepath.Join(root, "cache"), filepath.Join(root, "tmp")
	// On Windows these inherit the application folder's protected DACL; the
	// chmod keeps the Unix mode at 0700 whatever the umask.
	for _, directory := range []string{root, cache, temporary} {
		if directory != root {
			if err := os.Mkdir(directory, 0o700); err != nil {
				return "", "", "", cleanup, errors.Join(err, cleanup())
			}
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return "", "", "", cleanup, errors.Join(err, cleanup())
		}
	}
	return root, cache, temporary, cleanup, nil
}

// ValidateRcloneVaultConfig checks that the vault's private rclone config file
// is present and usable; it deliberately does not contact the provider. OAuth
// authorization discovers the account, drive, or namespace for the vault's
// physical address once. After that, pinned rclone owns this opaque file and
// its token refresh, and Replicaro does not reparse its credential fields.
// Every attached vault is still verified by the engine's native repository
// identity and the protected sidecar. Probing the provider on every command
// would mainly catch someone replacing or reauthorizing the config by hand as
// the same OS user, and would not strengthen that vault verification. Local
// file checks plus the normal engine checks are the intended limit for attached
// operations.
func ValidateRcloneVaultConfig(ctx context.Context, repo models.Repository) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	binding, err := openRcloneVaultConfigBindingLocal(repo)
	if err != nil {
		return err
	}
	return binding.Close()
}

func openRcloneVaultConfigBindingLocal(repo models.Repository) (*RcloneVaultConfigBinding, error) {
	if repo.Engine != ResticID || !IsResticRcloneConnector(repo.Connector) {
		return nil, fmt.Errorf("%w: repository is not a Restic rclone connector", ErrUnsupported)
	}
	// Only the sign-in providers have a private config. An Any Rclone Remote
	// vault uses the user's own file and must never get one.
	if !IsRcloneNativeLoginProvider(repo.Connector) {
		return nil, fmt.Errorf("%w: repository has no private rclone config", ErrUnsupported)
	}
	if _, err := NormalizeRcloneProviderOptions(repo.Connector, repo.ConnectorOptions); err != nil {
		return nil, reconnectRequired(fmt.Errorf("rclone vault identity is invalid: %w", err))
	}
	config, err := rcloneConfigPathForRepository(repo)
	if err != nil {
		return nil, localRcloneBindingFailure("rclone vault requires native reconnect", err)
	}
	if repo.RcloneConfigPath == "" {
		expected, pathErr := RcloneVaultConfigPath(repo.ID)
		if pathErr != nil || config != expected {
			return nil, reconnectRequired(fmt.Errorf("rclone vault config binding is invalid"))
		}
	}
	// Check the path again after the native command rather than holding the
	// file: rclone replaces it with a rename when it refreshes the token.
	check := func() error {
		if err := validateRcloneVaultFile(config); err != nil {
			return localRcloneBindingFailure("rclone vault requires native reconnect", err)
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	return &RcloneVaultConfigBinding{
		path:       config,
		revalidate: func(context.Context) error { return check() },
	}, nil
}

// OpenRcloneVaultConfigBinding validates a Restic-rclone config locally and
// selects its canonical private path. Revalidate checks the file again
// immediately before or after use. The vault's identity is confirmed by the
// native repository and the sidecar; a provider listing here would add nothing.
// The binding keeps no file or directory open.
func OpenRcloneVaultConfigBinding(
	ctx context.Context,
	repo models.Repository,
) (*RcloneVaultConfigBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openRcloneVaultConfigBindingLocal(repo)
}

// RcloneVaultCredentialsReady reports whether an attached vault is ready to
// use: its address options are complete and hold no secrets, and its private
// rclone config file is present and usable. Whether the provider is reachable
// is left to the operation itself.
func RcloneVaultCredentialsReady(ctx context.Context, repo models.Repository) bool {
	if repo.Engine != ResticID || !IsRcloneNativeLoginProvider(repo.Connector) {
		return false
	}
	normalized, err := NormalizeRcloneProviderOptions(
		repo.Connector, repo.ConnectorOptions,
	)
	if err != nil {
		return false
	}
	provider, _ := RcloneProvider(repo.Connector)
	for field := range provider.SecretFields {
		if normalized[field] != "" {
			return false
		}
	}
	_ = ctx
	return checkRcloneVaultConfig(repo.ID) == nil
}

func promoteRcloneVaultConfig(
	ctx context.Context,
	binary, stagedConfig, repositoryID string,
) (RcloneConfigActivation, error) {
	_ = ctx
	_ = binary
	return publishRcloneVaultConfig(stagedConfig, repositoryID)
}

// EnsureRcloneSidecarConfig returns the vault-owned opaque native config.
// Restic-rclone sidecars reuse their exact private repository config.
func EnsureRcloneSidecarConfig(ctx context.Context, repo models.Repository, binary string) (string, error) {
	if IsResticRcloneConnector(repo.Connector) {
		if err := ValidateRcloneVaultConfig(ctx, repo); err != nil {
			return "", err
		}
		return rcloneConfigPathForRepository(repo)
	}
	if repo.RcloneConfigPath != "" {
		if err := validateRcloneVaultFile(repo.RcloneConfigPath); err != nil {
			return "", err
		}
		return repo.RcloneConfigPath, nil
	}
	binding, err := openNonResticRcloneSidecarConfigBinding(ctx, repo, binary)
	if err != nil {
		return "", err
	}
	path := binding.Path()
	if err := binding.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func openNonResticRcloneSidecarConfigBinding(
	ctx context.Context,
	repo models.Repository,
	binary string,
) (*RcloneVaultConfigBinding, error) {
	config, err := RcloneVaultConfigPath(repo.ID)
	if err != nil {
		return nil, err
	}
	if checkErr := validateRcloneVaultFile(config); checkErr == nil {
		return nonResticRcloneSidecarBinding(repo.ID, config), nil
	} else if !errors.Is(checkErr, os.ErrNotExist) {
		return nil, checkErr
	}
	config, err = prepareRcloneVaultDirectory(repo.ID)
	if err != nil {
		return nil, err
	}
	_, cache, temporary, cleanup, err := privateRcloneOperationDirectories()
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	binding, err := touchRcloneVaultSidecarConfig(
		ctx, binary, repo.ID, config, cache, temporary,
	)
	if err != nil {
		return nil, fmt.Errorf("native rclone could not establish the vault sidecar config")
	}
	return binding, nil
}

func nonResticRcloneSidecarBinding(
	repositoryID, config string,
) *RcloneVaultConfigBinding {
	return &RcloneVaultConfigBinding{
		path: config,
		revalidate: func(context.Context) error {
			return checkRcloneVaultConfig(repositoryID)
		},
	}
}

// OpenRcloneSidecarConfigBinding establishes the existing vault-specific
// sidecar config at its ordinary canonical path without retaining an opened
// file or directory across a native command.
func OpenRcloneSidecarConfigBinding(
	ctx context.Context,
	repo models.Repository,
	binary string,
) (*RcloneVaultConfigBinding, error) {
	if IsResticRcloneConnector(repo.Connector) {
		return OpenRcloneVaultConfigBinding(ctx, repo)
	}
	if repo.RcloneConfigPath != "" {
		return nil, fmt.Errorf("staged non-Restic sidecar config cannot select an attached binding")
	}
	return openNonResticRcloneSidecarConfigBinding(ctx, repo, binary)
}

// OpenExistingRcloneStatisticsConfigBinding admits only an already-existing
// attached vault config. Unlike the sidecar binding it never creates a vault
// directory, touches a config, or initializes any remote. OAuth repositories
// keep their canonical private config path and the same file checks.
func OpenExistingRcloneStatisticsConfigBinding(
	ctx context.Context,
	repo models.Repository,
) (*RcloneVaultConfigBinding, error) {
	if IsResticRcloneConnector(repo.Connector) {
		return OpenRcloneVaultConfigBinding(ctx, repo)
	}
	if repo.RcloneConfigPath != "" {
		return nil, fmt.Errorf("staged non-Restic config cannot select an attached statistics binding")
	}
	config, err := RcloneVaultConfigPath(repo.ID)
	if err != nil {
		return nil, err
	}
	if err := validateRcloneVaultFile(config); err != nil {
		return nil, err
	}
	return nonResticRcloneSidecarBinding(repo.ID, config), nil
}

// NewRclonePreviewSidecarConfig creates a temporary rclone config (via
// "rclone config touch") in a private operation directory, for inspecting a
// vault before it is attached. Random preview IDs never map to a durable vault
// config path.
func NewRclonePreviewSidecarConfig(
	ctx context.Context,
) (string, func() error, error) {
	binary, err := rcloneBinary(pathFor(RcloneComponentID))
	if err != nil {
		return "", nil, err
	}
	config, _, _, cleanup, err := newTemporaryRcloneConfig(ctx, binary)
	return config, cleanup, err
}

// newTemporaryRcloneConfig makes an empty native config with "rclone config
// touch" inside a fresh private operation directory, and returns it with that
// directory's cache and temp folders. Cleanup removes the whole directory.
// The connect preview and Restic's WebDAV transport both define their remotes
// entirely through RCLONE_CONFIG_* variables on top of this file, so it never
// holds a setting or credential.
func newTemporaryRcloneConfig(
	ctx context.Context, binary string,
) (config, cache, temporary string, cleanup func() error, err error) {
	root, cache, temporary, cleanup, err := privateRcloneOperationDirectories()
	if err != nil {
		return "", "", "", nil, err
	}
	config = filepath.Join(root, "rclone.conf")
	if _, err := runRcloneVaultConfigCommand(
		ctx, binary,
		[]string{"config", "touch", "--config", config, "--cache-dir", cache,
			"--temp-dir", temporary, "--log-level", "ERROR"},
		nil, "", time.Minute, RcloneComponentID,
	); err != nil {
		// Keep the fixed message but the cause too, so a cancelled command is
		// still reported as interrupted rather than as a setup failure.
		return "", "", "", cleanup, errors.Join(
			&privateOutputError{message: "native rclone could not establish temporary rclone config", cause: err},
			cleanup(),
		)
	}
	if err := hardenNewRcloneConfigFile(config); err != nil {
		return "", "", "", cleanup, errors.Join(err, cleanup())
	}
	if err := validateRcloneVaultFile(config); err != nil {
		return "", "", "", cleanup, errors.Join(err, cleanup())
	}
	return config, cache, temporary, cleanup, nil
}

// RemoveRcloneVaultConfig removes one vault's config folder,
// rclone/vaults/<uuid>, with everything in it, including rclone's leftover
// save files. The UUID check keeps the removal inside the vault-config root.
// os.RemoveAll deletes a link in that folder (or a folder that is itself a
// link) without touching what it points to.
func RemoveRcloneVaultConfig(repositoryID string) error {
	if !validRepositoryUUID(repositoryID) {
		return fmt.Errorf("rclone vault repository ID must be a canonical UUID")
	}
	config, err := RcloneVaultConfigPath(repositoryID)
	if err != nil {
		return err
	}
	return os.RemoveAll(filepath.Dir(config))
}

// ReconcileRcloneVaultConfigs cleans up the config folder of every canonical
// vault UUID in the vault-config root that has no attached vault or workflow
// owner, left behind when a removal or an abandoned creation was interrupted.
// Names that aren't canonical UUIDs are left alone.
//
// ownerIDs must be the complete owner list. The caller has to stop, rather
// than pass a partial or empty set, when the list can't be read; otherwise a
// live vault would lose its sign-in. A folder that can't be cleaned up doesn't
// stop the others; the joined error is only logged at startup.
func ReconcileRcloneVaultConfigs(ownerIDs map[string]bool) error {
	root, err := appdata.RcloneVaultConfigRoot()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var result error
	for _, entry := range entries {
		id := entry.Name()
		if !validRepositoryUUID(id) || ownerIDs[id] {
			continue
		}
		if err := removeOrphanedRcloneVaultFolder(filepath.Join(root, id)); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

// removeOrphanedRcloneVaultFolder removes only what Replicaro and rclone put
// in a vault's config folder: rclone.conf and rclone's leftover save files
// (the same names publication clears). The folder itself goes only once it's
// empty. Unlike RemoveRcloneVaultConfig, nobody asked for this removal, and
// the folder may hold a file the user put there by mistake, so a folder with
// anything else in it is reported and left in place.
//
// Each removal is os.Remove, which deletes a link rather than its target. An
// entry that isn't a plain folder (a link, junction, or stray file) is removed
// itself, without looking inside, so a link's target is never touched.
func removeOrphanedRcloneVaultFolder(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if info.Mode().Type() != fs.ModeDir {
		return os.Remove(directory)
	}
	if err := os.Remove(filepath.Join(directory, "rclone.conf")); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	removeRcloneConfigLeftovers(directory)
	if err := os.Remove(directory); err != nil {
		return fmt.Errorf("leave orphaned rclone vault folder in place: %w", err)
	}
	return nil
}
