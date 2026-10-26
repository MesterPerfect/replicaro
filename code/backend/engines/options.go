package engines

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/local/replicaro/models"
)

// allowedBackupFlags lists the advanced backup flags each engine accepts. None
// of them takes a separate value; only Restic's --verbose accepts an inline
// "=level".
var allowedBackupFlags = map[string]map[string]bool{
	ResticID: {"--verbose": true, "--no-scan": true, "--exclude-caches": true, "--one-file-system": true, "--ignore-ctime": true, "--ignore-inode": true, "--with-atime": true, "--skip-if-unchanged": true},
	KopiaID:  {"--fail-fast": true},
}

// retiredBackupFlags lists Advanced options that a job setting now replaces,
// with the name of that setting. Saving a job refuses them
// (RejectRetiredBackupOptions); everything else (backups, profile publication
// and loading, recovery and import) still accepts them through
// allowedBackupFlags above, so jobs saved with one keep working until they
// are edited. Keep a retired flag in allowedBackupFlags for that reason, and
// don't convert saved jobs at startup.
var retiredBackupFlags = map[string]map[string]string{
	ResticID: {"--exclude-caches": "Skip the contents of any folder that contains a CACHEDIR.TAG file"},
}

// RetiredBackupOptionCode is the API error code of a job save refused by
// RejectRetiredBackupOptions. The UI builds its translated message from the
// code and the flag, and quotes the replacement setting's label from its own
// catalog, so the quote always matches the checkbox the user sees.
const RetiredBackupOptionCode = "retired_backup_option"

// RetiredBackupOptionError is a job save refused because its Advanced options
// use a retired flag. Error() is the English text API clients read; Flag is
// sent next to the code so the UI can fill in its own translation.
type RetiredBackupOptionError struct {
	// Flag is the retired flag in lower case, as the message shows it.
	Flag string
	// Replacement is the English label of the setting to use instead.
	Replacement string
}

func (e *RetiredBackupOptionError) Error() string {
	return fmt.Sprintf("%s can no longer be set in Advanced CLI options. Use \"%s\" instead.", e.Flag, e.Replacement)
}

// RejectRetiredBackupOptions refuses a job's Advanced options that use a
// retired flag, naming the setting to use instead. The error is always a
// *RetiredBackupOptionError.
func RejectRetiredBackupOptions(settings models.EngineSettings) error {
	for engineID, section := range settings {
		retired := retiredBackupFlags[engineID]
		if len(retired) == 0 {
			continue
		}
		tokens, err := optionTokens(section.AdditionalOptions)
		if err != nil {
			// Malformed options get their own message from validateOptions.
			continue
		}
		for _, token := range tokens {
			flag, _, _ := strings.Cut(token, "=")
			if replacement, ok := retired[strings.ToLower(flag)]; ok {
				return &RetiredBackupOptionError{Flag: strings.ToLower(flag), Replacement: replacement}
			}
		}
	}
	return nil
}

var disabledBackupFlags = map[string]bool{
	"--use-fs-snapshot": true,
}

var alwaysProtectedFlags = map[string]bool{
	"--repo": true, "-r": true, "--repository": true, "--password": true, "-p": true, "--password-file": true, "--password-command": true,
	"--config-file": true, "--cache-directory": true, "--source": true, "--target": true, "--to": true, "--tag": true, "--tags": true,
	"--exclude": true, "--exclude-file": true, "--include": true, "--include-file": true, "--path": true, "--json": true, "--output": true,
	"--compression": true, "--no-compression": true, "--encryption": true, "--repository-version": true, "--read-data": true, "--check": true,
	"--stdin-from-command": true, "--stdin-filename": true, "--files-from": true, "--files-from-raw": true, "--files-from-verbatim": true,
	"--time": true, "--override-source": true, "--pin": true, "--action": true, "--policy": true, "--enable-actions": true,
	"--log-file": true, "--log-dir": true, "--output-format": true, "--command": true, "--stdin-command": true,
}

func validateOptions(engine string, options []string) error {
	allowed, known := allowedBackupFlags[engine]
	if !known {
		return fmt.Errorf("unsupported engine %q", engine)
	}
	tokens, err := optionTokens(options)
	if err != nil {
		return fmt.Errorf("%s advanced options: %w", engine, err)
	}
	seen := map[string]bool{}
	for index := 0; index < len(tokens); index++ {
		token := tokens[index]
		if !strings.HasPrefix(token, "-") || token == "-" || strings.HasPrefix(token, "@") {
			return fmt.Errorf("%s advanced options must contain supported flags only", engine)
		}
		flag, hasValue := token, false
		if equal := strings.IndexByte(token, '='); equal >= 0 {
			flag, hasValue = token[:equal], true
		}
		flag = strings.ToLower(flag)
		if disabledBackupFlags[flag] {
			return fmt.Errorf("%s advanced option %q is disabled because VSS filesystem snapshots are not supported", engine, flag)
		}
		// Protect snapshot timestamp override via exact --time above. A substring
		// ban on "time" also rejects the explicitly supported --ignore-ctime and
		// --with-atime flags; the closed allowlist below still rejects unknowns.
		if alwaysProtectedFlags[flag] || strings.Contains(flag, "pass") || strings.Contains(flag, "secret") || strings.Contains(flag, "token") || strings.Contains(flag, "credential") || strings.Contains(flag, "repository") || strings.Contains(flag, "repo") || strings.Contains(flag, "config") || strings.Contains(flag, "limit") || strings.Contains(flag, "concurr") {
			return fmt.Errorf("%s advanced option %q is controlled by Replicaro", engine, flag)
		}
		if !allowed[flag] || (len(flag) > 2 && strings.HasPrefix(flag, "-") && strings.HasPrefix(flag[1:], "-") == false && len(flag) > 2) {
			return fmt.Errorf("%s advanced option %q is not allowed for backup", engine, flag)
		}
		if hasValue {
			if !(engine == ResticID && flag == "--verbose" && validResticVerbosity(token[strings.IndexByte(token, '=')+1:])) {
				return fmt.Errorf("%s advanced option %q does not accept a value", engine, flag)
			}
		}
		duplicateAllowed := engine == ResticID && flag == "--verbose"
		if seen[flag] && !duplicateAllowed {
			return fmt.Errorf("%s advanced option %q is duplicated", engine, flag)
		}
		seen[flag] = true
	}
	return nil
}

func validResticVerbosity(value string) bool {
	return value == "0" || value == "1" || value == "2"
}

func optionTokens(lines []string) ([]string, error) {
	var result []string
	for _, line := range lines {
		var token strings.Builder
		quoted := rune(0)
		escaped := false
		flush := func() {
			if token.Len() > 0 {
				result = append(result, token.String())
				token.Reset()
			}
		}
		for _, r := range line {
			if unicode.IsControl(r) {
				return nil, fmt.Errorf("control characters are not allowed")
			}
			if escaped {
				token.WriteRune(r)
				escaped = false
				continue
			}
			if r == '\\' && quoted != '\'' {
				escaped = true
				continue
			}
			if quoted != 0 {
				if r == quoted {
					quoted = 0
				} else {
					token.WriteRune(r)
				}
				continue
			}
			switch r {
			case '\'', '"':
				quoted = r
			case ' ', '\t':
				flush()
			default:
				token.WriteRune(r)
			}
		}
		if escaped || quoted != 0 {
			return nil, fmt.Errorf("malformed quoting")
		}
		flush()
	}
	return result, nil
}

func normalizedOptions(settings models.EngineJobSettings) ([]string, error) {
	options, err := optionTokens(settings.AdditionalOptions)
	if err != nil {
		return nil, err
	}
	return options, nil
}

func validateEngineSettingsSection(id string, value models.EngineJobSettings) error {
	if !models.ValidEngine(id) {
		return fmt.Errorf("unknown engine settings key %q", id)
	}
	return validateOptions(id, value.AdditionalOptions)
}

// ValidatePortableJobSettings requires settings for every represented engine,
// while retaining valid settings for known engines whose vaults are not
// currently connected.
func ValidatePortableJobSettings(settings models.EngineSettings, represented map[string]bool) error {
	for id := range represented {
		if !models.ValidEngine(id) {
			return fmt.Errorf("unknown represented engine %q", id)
		}
		if _, ok := settings[id]; !ok {
			return fmt.Errorf("engine settings for %s are required", id)
		}
	}
	for id, value := range settings {
		if err := validateEngineSettingsSection(id, value); err != nil {
			return err
		}
	}
	return nil
}

func ValidateJobSettings(settings models.EngineSettings, represented map[string]bool) error {
	if err := ValidatePortableJobSettings(settings, represented); err != nil {
		return err
	}
	for id := range settings {
		if !represented[id] {
			return fmt.Errorf("engine settings for %s are not represented by this job's vaults", id)
		}
	}
	if len(settings) != len(represented) {
		return fmt.Errorf("engine settings must contain exactly one section for each represented engine")
	}
	return nil
}
