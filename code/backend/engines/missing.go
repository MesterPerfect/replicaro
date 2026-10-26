package engines

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/local/replicaro/models"
	"github.com/local/replicaro/vaultidentity"
)

// RepositoryMissing is the only creation classifier used by the API. It is
// deliberately conservative: authentication, authorization, credential,
// network, timeout, and ambiguous failures are never treated as absence.
//
// For a filesystem vault it reads the vault path directly and can block
// indefinitely on a hung share, so code that holds a vault lock or serves a
// request should call RepositoryMissingContext instead.
func RepositoryMissing(repo models.Repository, output string) bool {
	switch repo.Engine {
	case ResticID:
		return resticRepositoryMissing(repo, output)
	case KopiaID:
		lower := repositoryMissingMessageText(repo, output)
		if containsUnsafeFailure(lower) {
			return false
		}
		if repo.Connector != "" && repo.Connector != "fs" {
			return strings.Contains(lower, "repository not initialized in the provided storage")
		}
		if KopiaRepositoryExists(repo.Location) {
			return false
		}
		return localRepositoryMissing(repo.Location) && containsAny(lower, "config file", "config not found", "repository")
	default:
		return false
	}
}

// RepositoryAccessRejected recognizes only native output that affirmatively
// attributes repository validation failure to authentication or authorization.
// Ambiguous transport and service failures must remain unclassified.
func RepositoryAccessRejected(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		for _, prefix := range []string{"fatal: ", "error: ", "error "} {
			line = strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
		switch line {
		case "wrong password or no key found",
			"wrong password", "incorrect password", "invalid password", "wrong passphrase", "no key found",
			"authentication failed", "access denied", "unauthorized", "forbidden", "accessdenied",
			"request failed with status code: 403", "request failed with statuscode=403":
			return true
		}
		if sshPermissionDeniedPattern.MatchString(line) {
			return true
		}
	}
	return false
}

var sshPermissionDeniedPattern = regexp.MustCompile(`^(?:[^[:space:]:]+@[^[:space:]:]+: )?permission denied \((?:publickey|keyboard-interactive|password)(?:,(?:publickey|keyboard-interactive|password))*\)\.?$`)

func resticRepositoryMissing(repo models.Repository, output string) bool {
	lower := repositoryMissingMessageText(repo, output)
	if containsUnsafeFailure(lower) {
		return false
	}
	if repo.Connector != "" && repo.Connector != "fs" {
		return strings.Contains(lower, "repository does not exist") &&
			strings.Contains(lower, "unable to open config file")
	}
	if !localRepositoryMissing(repo.Location) {
		return false
	}
	return containsAny(lower, "config file", "repository does not exist")
}

// repositoryMissingMessageText returns the lowercased native output with the
// vault's own path taken out. The engines quote the vault path in their
// messages, and the classifiers look for words such as "secret", "token" or
// "403", so a vault folder named "Secrets" or "20240315" would otherwise be
// read as a credential or HTTP failure. Only the engine's own wording decides.
//
// The path is replaced with NUL rather than removed: no marker contains NUL,
// so the replacement can neither join the text around it into a new marker
// nor hide a marker the engine wrote outside the path.
func repositoryMissingMessageText(repo models.Repository, output string) string {
	lines := strings.Split(strings.ToLower(output), "\n")
	kept := make([]string, 0, len(lines))
	for index, line := range lines {
		// Restic follows a missing repository with this question and then the
		// repository location alone on the next line.
		if index > 0 && strings.TrimSpace(lines[index-1]) == "is there a repository at the following location?" {
			continue
		}
		kept = append(kept, line)
	}
	text := strings.Join(kept, "\n")
	location := strings.TrimSpace(repo.Location)
	if location == "" {
		return text
	}
	spellings := []string{repo.Location, location}
	if repo.Connector == "" || repo.Connector == "fs" {
		// The engines join a local vault path with a file name before printing
		// it, which drops a trailing separator.
		spellings = append(spellings, filepath.Clean(location))
	} else if parsed, err := url.Parse(location); err == nil {
		// Cloud SDK errors quote the request URL, which holds the vault's
		// path in plain or escaped form.
		for _, path := range []string{parsed.Path, parsed.EscapedPath()} {
			if path = strings.TrimRight(path, "/"); path != "" {
				spellings = append(spellings, path)
			}
		}
		if repo.Connector == "sftp" {
			// Restic prints an SFTP path in home mode relative to the home
			// folder, without the leading "/" the location URL has. The
			// trailing "/" is kept so that a short vault path such as "tokens"
			// only matches as a path, never inside a real "token" message.
			if address, err := vaultidentity.ResolveEffectiveAddress(repo.Connector, location, repo.ConnectorOptions); err == nil && address.Prefix != "" {
				spellings = append(spellings, address.Prefix+"/")
			}
		}
	}
	// Longest first, so a shorter spelling cannot split a longer one.
	sort.Slice(spellings, func(i, j int) bool { return len(spellings[i]) > len(spellings[j]) })
	for _, spelling := range spellings {
		text = strings.ReplaceAll(text, strings.ToLower(spelling), "\x00")
	}
	return text
}

func localRepositoryMissing(location string) bool {
	if strings.TrimSpace(location) == "" {
		return false
	}
	info, err := os.Stat(location)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil || !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(location)
	if err != nil {
		return false
	}
	return len(entries) == 0
}

func containsUnsafeFailure(lower string) bool {
	return containsAny(lower,
		"wrong password", "incorrect password", "wrong passphrase", "invalid password", "access denied", "permission denied",
		"unauthorized", "forbidden", "403", "authentication", "authorization", "credential", "credentials", "password file",
		"secret", "token", "api key", "network is unreachable", "network error", "network failure", "timeout", "timed out", "connection refused", "connection reset",
		"tls", "certificate", "temporary failure", "dns")
}

func containsAny(value string, markers ...string) bool {
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
