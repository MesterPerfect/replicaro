package jobscript

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/local/replicaro/command"
)

// ValidatePath accepts only an absolute path, with no surrounding whitespace,
// to an existing regular file. On POSIX the stored path itself must be
// executable so the kernel runs it directly, shebang included.
func ValidatePath(path string) error {
	if path == "" {
		return nil
	}
	if strings.TrimSpace(path) != path || !filepath.IsAbs(path) {
		return fmt.Errorf("script path must be an exact absolute path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("script path must name an existing file")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("script path must name a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("POSIX script path must be executable and use a native executable or shebang")
	}
	if runtime.GOOS == "windows" {
		extension := strings.ToLower(filepath.Ext(path))
		if extension != ".bat" && extension != ".cmd" && extension != ".ps1" && extension != ".exe" && extension != ".com" {
			return fmt.Errorf("Windows script path must be a batch, PowerShell, or executable file")
		}
		if (extension == ".bat" || extension == ".cmd") && strings.ContainsAny(path, "&|<>^%!\"") {
			return fmt.Errorf("Windows batch script path contains characters unsafe for fixed cmd.exe invocation")
		}
	}
	return nil
}

func ValidateDefinition(before string, beforeRequired bool, after string, afterRequired bool) error {
	if before == "" && beforeRequired {
		return fmt.Errorf("before-script required checkbox needs a script path")
	}
	if after == "" && afterRequired {
		return fmt.Errorf("after-script required checkbox needs a script path")
	}
	if err := ValidatePath(before); err != nil {
		return fmt.Errorf("before script: %w", err)
	}
	if err := ValidatePath(after); err != nil {
		return fmt.Errorf("after script: %w", err)
	}
	return nil
}

// Run executes one validated stored path with fixed platform handling. It
// supplies no arguments, runs the script in its own folder with Replicaro's
// environment, and never returns script output.
func Run(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if path == "" {
		return errors.New("script file is missing or unusable")
	}
	if err := ValidatePath(path); err != nil {
		return errors.New("script file is missing or unusable")
	}
	executable, args, err := invocation(runtime.GOOS, os.Getenv("SystemRoot"), path)
	if err != nil {
		return err
	}
	// The script's own folder is the one working directory that means the same
	// thing on every OS. Replicaro's own is whatever launched it (System32 from
	// the Windows Run key, / for a macOS app), so a relative path in a script
	// would otherwise depend on how Replicaro was started.
	err = command.RunDiscardOutput(command.ContextWithFinalCancellationAdmission(ctx), executable, args, filepath.Dir(path), "job script")
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ctx.Err()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return errors.New("script completed unsuccessfully")
	}
	return errors.New("script launch failed")
}

// invocation returns the program and arguments that run a validated script on
// goos. POSIX files and Windows executables run directly; Windows batch and
// PowerShell files run through their interpreter under systemRoot.
func invocation(goos, systemRoot, path string) (string, []string, error) {
	if goos != "windows" {
		return path, []string{}, nil
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd":
		if systemRoot == "" {
			return "", nil, errors.New("script launch failed")
		}
		// Keep the fixed command verb outside the quoted path. cmd.exe's /S
		// handling otherwise removes the only quote pair around a path with
		// spaces before it resolves the batch file.
		return filepath.Join(systemRoot, "System32", "cmd.exe"), []string{"/D", "/S", "/C", "call", path}, nil
	case ".ps1":
		if systemRoot == "" {
			return "", nil, errors.New("script launch failed")
		}
		// Windows' default execution policy (Restricted on client editions)
		// refuses every .ps1 file, so a hook the user chose would never run.
		// Bypass applies to this one PowerShell process only, and a policy set
		// by Group Policy still overrides it. -File and the path stay last,
		// because PowerShell passes everything after -File to the script.
		return filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
			[]string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, nil
	}
	return path, []string{}, nil
}
