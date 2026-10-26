import { t } from "../i18n";

export interface MarkerFileValues {
	skipNoBackupFolders: boolean;
	skipCacheDirFolders: boolean;
	skipCustomMarker: boolean;
	skipMarkerFileName: string;
}

// Names that already have their own box. The backend refuses them as the
// custom name too (models.ValidateSkipMarkerFileName); CACHEDIR.TAG as a
// custom name would make Restic skip on presence alone, without the
// signature check its own box gets.
const reservedMarkerNames = new Set([".nobackup", "CACHEDIR.TAG", ".kopiaignore"]);

// Go's unicode.IsControl: the C0 and C1 control ranges.
function hasControlCharacter(value: string) {
	for (const character of value) {
		const code = character.codePointAt(0) ?? 0;
		if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
	}
	return false;
}

// markerFileNameError mirrors the backend rule for the custom marker name and
// returns the translated message, or "" for a valid name. One plain file name:
// no folder separators, no ":" (Restic reads "name:header" as a name plus a
// required first line), no wildcards, not "." or "..", no spaces at either
// end and no control characters. Keep it in step with the backend.
export function markerFileNameError(name: string): string {
	if (name === "" || name === "." || name === ".." || name.trim() !== name ||
		/[/\\:*?[\]{}]/.test(name) || hasControlCharacter(name)) {
		return t("ui.protect.markerFiles.customInvalid");
	}
	if (reservedMarkerNames.has(name)) return t("ui.protect.markerFiles.customTaken");
	return "";
}
