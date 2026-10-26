package engines

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/local/replicaro/appdata"
	"github.com/local/replicaro/models"
)

type integrityKopiaConfigKey struct{}

const integrityKopiaConfigDirectoryName = "integrity-check"

// PrepareIntegrityCheck creates the run-local resources and applies the native
// cache policy required before an engine's full check. Its output and error
// belong to orchestration preparation; the later Check call reports only the
// requested native verification command.
func PrepareIntegrityCheck(
	ctx context.Context,
	engine Engine,
	repo models.Repository,
) (context.Context, string, func() error, error) {
	checkContext, cleanup, err := prepareIntegrityCheckResources(ctx, repo)
	if err != nil {
		return nil, "", nil, err
	}
	if repo.Engine == ResticID {
		return checkContext, "", cleanup, nil
	}
	target := engine
	if public, ok := engine.(*publicEngine); ok {
		target = public.Engine
	}
	kopia, ok := target.(*kopiaEngine)
	if !ok {
		return checkContext, "", cleanup, fmt.Errorf("Kopia integrity preparation requires the Kopia engine")
	}
	output, err := kopia.prepareIntegrityCheckCache(checkContext, repo)
	return checkContext, output, cleanup, err
}

// prepareIntegrityCheckResources creates only the operation-owned filesystem
// resources. Restic disables its cache with --no-cache and needs no artifact.
func prepareIntegrityCheckResources(ctx context.Context, repo models.Repository) (context.Context, func() error, error) {
	if repo.Engine == ResticID {
		return ctx, func() error { return nil }, nil
	}
	if repo.Engine != KopiaID {
		return nil, nil, fmt.Errorf("unsupported integrity-check engine %q", repo.Engine)
	}
	if strings.TrimSpace(repo.ID) == "" {
		return nil, nil, fmt.Errorf("Kopia vault ID is required for isolated integrity configuration")
	}

	// Kopia's repository configuration can contain native credential material.
	// Keep the copy under the vault's already-private configuration directory so
	// it receives the same filesystem protection as the canonical file.
	root, err := appdata.Directory(filepath.Join("engines", KopiaID, repo.ID, "config"))
	if err != nil {
		return nil, nil, fmt.Errorf("prepare Kopia integrity configuration root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, nil, fmt.Errorf("secure integrity artifact root: %w", err)
	}
	// A fixed child bounds crash residue to one private folder. The next check
	// removes whatever is left there before creating its own copy.
	//
	// Cleanup is a plain os.RemoveAll on that one recognized name.
	// os.RemoveAll never follows links: a link at the child, or anywhere
	// inside it, is removed as a link and its target is left alone. There are
	// deliberately no link checks on the config folder or this child. They
	// only matter if someone with access to the computer swaps these folders
	// for links while a check runs, which Replicaro doesn't defend against.
	// Don't add them back without a product decision.
	child, err := integrityArtifactPath(root, integrityKopiaConfigDirectoryName)
	if err != nil {
		return nil, nil, err
	}
	if err := os.RemoveAll(child); err != nil {
		return nil, nil, fmt.Errorf("remove stale Kopia integrity configuration: %w", err)
	}
	if err := os.Mkdir(child, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create Kopia integrity configuration directory: %w", err)
	}
	if err := os.Chmod(child, 0o700); err != nil {
		_ = os.RemoveAll(child)
		return nil, nil, fmt.Errorf("secure Kopia integrity configuration directory: %w", err)
	}
	canonical := filepath.Join(root, "repository.config")
	operationConfig := filepath.Join(child, "repository.config")
	// The copier only accepts a bounded regular file as its source, and it
	// writes the copy owner-only and synced, the same way reconnect does.
	if err := copyKopiaReconnectConfig(canonical, operationConfig); err != nil {
		_ = os.RemoveAll(child)
		return nil, nil, fmt.Errorf("copy Kopia integrity configuration: %w", err)
	}
	cleanup := func() error {
		if err := os.RemoveAll(child); err != nil {
			return fmt.Errorf("remove Kopia integrity configuration: %w", err)
		}
		return nil
	}
	return context.WithValue(ctx, integrityKopiaConfigKey{}, operationConfig), cleanup, nil
}

// secureIntegrityKopiaConfig runs after Kopia's `cache set` has rewritten the
// operation copy. The copy still has to be a non-empty regular file within the
// config size bound before verification uses it; Lstat keeps the chmod from
// landing on anything other than the file Kopia wrote.
func secureIntegrityKopiaConfig(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect operation-owned Kopia integrity configuration: %w", err)
	}
	if !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maximumKopiaReconnectConfigBytes {
		return fmt.Errorf("operation-owned Kopia integrity configuration is not a bounded regular file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure operation-owned Kopia integrity configuration: %w", err)
	}
	return nil
}

// integrityArtifactPath joins name onto root and makes sure the result is a
// direct child of root, so the RemoveAll calls above can only ever reach that
// one folder under the vault's config directory.
func integrityArtifactPath(root, name string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve integrity artifact root: %w", err)
	}
	absoluteChild := filepath.Join(absoluteRoot, name)
	relative, err := filepath.Rel(absoluteRoot, absoluteChild)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) ||
		filepath.Dir(relative) != "." {
		return "", fmt.Errorf("integrity artifact is outside its operation root")
	}
	return absoluteChild, nil
}

func integrityCheckKopiaConfig(ctx context.Context) string {
	value, _ := ctx.Value(integrityKopiaConfigKey{}).(string)
	return value
}
