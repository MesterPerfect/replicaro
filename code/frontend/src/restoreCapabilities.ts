import type { EngineDescriptor, Repository } from "./types";
import { t } from "./i18n";

export function restoreCapability(repository: Repository | undefined, engines: EngineDescriptor[]) {
	return engines.find((engine) => engine.id === repository?.engine)?.capabilities.restore;
}

export function defaultConflictMode(repository: Repository | undefined, engines: EngineDescriptor[]) {
	const modes = restoreCapability(repository, engines)?.conflictModes ?? [];
	return modes.find((mode) => mode.default)?.id ?? modes[0]?.id ?? "";
}

export function restoreConflictModeLabel(mode: { id: string; label: string }) {
	if (mode.id === "always" || mode.id === "overwrite") return t("ui.restore.yesOverwrite");
	if (mode.id === "never" || mode.id === "no-overwrite") return t("ui.restore.doNotOverwrite");
	return mode.label;
}

// A selected item whose listed name contains U+FFFD is refused with this
// code. The engine listing replaced bytes that are not valid text with
// U+FFFD, so for Restic that name no longer matches the archived file; its
// folder can still be restored, which brings the file back with its real name.
// A Windows backend also refuses a Restic name containing a backslash.
export const RESTORE_SELECTION_NAME_INVALID = "restore_selection_name_invalid";

// restorableContainingFolder returns the nearest folder above a snapshot path
// whose own path has no U+FFFD, or "" when only the snapshot root is left.
// The snapshot root is not offered: restoring it is a whole-snapshot restore,
// which can lay files out differently from a selected restore. Backslashes are
// not skipped because these pages don't know the backend's OS; if an offered
// folder still contains one on Windows, the backend refuses it the same way.
export function restorableContainingFolder(path: string): string {
	const parts = path.split("/");
	for (let end = parts.length - 1; end > 0; end--) {
		const folder = parts.slice(0, end).join("/");
		if (!folder.includes("\uFFFD")) return folder;
	}
	return "";
}
