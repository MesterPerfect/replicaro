//go:build !windows

package appdata

import "os"

// secureEnsureDirectory creates any missing component with mode 0700 and
// follows symlinks like any other program would. The umask can only clear
// bits, so every folder created here is owner-only. Folders that already
// exist keep their owner and mode.
//
// There's deliberately no walk from / with Lstat, no refusal of symlinked or
// foreign-owned ancestors, and no chmod of existing folders. Those checks
// would only resist anyone with access to the computer (other local users or
// software running on it), which Replicaro doesn't try to defend against, and
// they break ordinary setups: /home linked to /var/home on ostree-based
// Fedora, a dotfile-managed ~/.config or ~/.local, NFS homes that show up as
// owned by nobody, and macOS's /var and /tmp, which are links into /private.
// So app-data folder setup makes no ownership or link checks; what it guards
// against is accidents. Deletion elsewhere uses os.Remove/os.RemoveAll, which
// never follow links.
//
// Running Replicaro as root with a regular user's HOME (for example through
// sudo) leaves root-owned folders in that user's home, and the user's own next
// start then fails on them with permission errors. That's a known trade-off;
// the fix is a chown of those folders back to the user. Don't add a guard for
// it, or ancestor, link, or owner checks here, without a product decision.
func secureEnsureDirectory(path string) error {
	return os.MkdirAll(path, 0o700)
}
