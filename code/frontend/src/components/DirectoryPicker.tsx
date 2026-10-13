import { t } from "../i18n";
import { useCallback, useEffect, useRef, useState } from "react";

import { APIError, browseDirectories } from "../services/api";
import type { DirectoryListing } from "../types";
import { Icon, Loading, Modal } from "./ui";

export function DirectoryField({
    value,
    onChange,
    placeholder,
	buttonLabel = t("ui.pages.protect.browse"),
	ariaLabel,
	disabled = false,
	readOnly = false,
	autoFocus = false,
}: {
    value: string;
    onChange: (value: string) => void;
    placeholder?: string;
	buttonLabel?: string;
	ariaLabel?: string;
	disabled?: boolean;
	readOnly?: boolean;
	autoFocus?: boolean;
}) {
    const [open, setOpen] = useState(false);

    return (
        <>
            <div className="directory-input">
                <input
                    type="text"
                    className="mono"
                    value={value}
                    placeholder={placeholder}
                    onChange={(event) => onChange(event.target.value)}
					aria-label={ariaLabel}
					disabled={disabled}
					readOnly={readOnly}
					autoFocus={autoFocus}
                />
                <button type="button" className="btn" disabled={disabled || readOnly} onClick={() => setOpen(true)}>
                    <Icon name="folder" size={14} /> {buttonLabel}
                </button>
            </div>
            {open && (
                <DirectoryPicker
                    initialPath={value}
                    onCancel={() => setOpen(false)}
                    onSelect={(path) => {
                        onChange(path);
                        setOpen(false);
                    }}
                />
            )}
        </>
    );
}

function DirectoryPicker({
    initialPath,
    onSelect,
    onCancel,
}: {
    initialPath: string;
    onSelect: (path: string) => void;
    onCancel: () => void;
}) {
    const [listing, setListing] = useState<DirectoryListing | null>(null);
    const [path, setPath] = useState(initialPath);
    const [error, setError] = useState("");
	// The backend ends a listing after 60 seconds when the folder (typically a
	// dead network share or a disconnected mapped drive) does not answer; the
	// OS call itself keeps running on the server. That case gets its own
	// localized message instead of the technical error text.
	const [notResponding, setNotResponding] = useState(false);
	const requestRef = useRef<{ controller: AbortController; generation: number } | null>(null);
	const generationRef = useRef(0);
	// The last folder that loaded. After a failed load it stays on screen under
	// the error, so the roots, Up one level, its subfolders and the footer are
	// still there to move on from.
	const loadedRef = useRef<DirectoryListing | null>(null);

	const cancelLoad = useCallback(() => {
		generationRef.current += 1;
		requestRef.current?.controller.abort();
		requestRef.current = null;
	}, []);

	const load = useCallback(async (requested: string) => {
		// keepError is set only for the fallback below, which must not clear the
		// error that caused it.
		const run = async (target: string, keepError: boolean): Promise<void> => {
			cancelLoad();
			const controller = new AbortController();
			const generation = ++generationRef.current;
			requestRef.current = { controller, generation };
			await Promise.resolve();
			if (generationRef.current !== generation || controller.signal.aborted) return;
			setListing(null);
			if (!keepError) {
				setError("");
				setNotResponding(false);
			}
			let fallback = false;
			try {
				const next = await browseDirectories(target, controller.signal);
				if (generationRef.current !== generation || controller.signal.aborted) return;
				loadedRef.current = next;
				setListing(next);
				setPath(next.current);
			} catch (reason) {
				if (generationRef.current !== generation || controller.signal.aborted || (reason as { name?: string })?.name === "AbortError") return;
				// The fallback's own failure keeps the first error, which names
				// the folder the user asked for.
				if (!keepError) {
					if (reason instanceof APIError && reason.code === "directory_not_responding") setNotResponding(true);
					else setError((reason as Error).message);
				}
				// When the very first folder fails there is nothing to keep, so
				// the default start folder (home, or / in Docker) is loaded once,
				// with the error still shown. Its own failure ends there. A kept
				// folder also goes back into the path box, since that is the
				// folder "Select this folder" returns.
				if (loadedRef.current) {
					setListing(loadedRef.current);
					setPath(loadedRef.current.current);
				} else fallback = target !== "";
			} finally {
				if (requestRef.current?.generation === generation) requestRef.current = null;
			}
			if (fallback) await run("", true);
		};
		await run(requested, false);
	}, [cancelLoad]);

    useEffect(() => {
		const timer = window.setTimeout(() => void load(initialPath), 0);
        return () => {
			window.clearTimeout(timer);
			cancelLoad();
        };
    }, [cancelLoad, initialPath, load]);

	const close = () => {
		cancelLoad();
		onCancel();
	};

    return (
        <Modal title={t("ui.components.directorypicker.choose.a.folder")} onClose={close} wide>
            <div className="directory-input" style={{ marginBottom: 12 }}>
                <input
                    className="mono"
                    type="text"
                    value={path}
                    onChange={(event) => setPath(event.target.value)}
                    onKeyDown={(event) => {
                        if (event.key === "Enter") void load(path);
                    }}
                    autoFocus
                />
                <button type="button" className="btn" onClick={() => void load(path)}>
                    {t("ui.components.directorypicker.go")}</button>
            </div>

            {error && <div className="inline-error">{error}</div>}
            {notResponding && <div className="inline-error" role="alert">
                <strong>{t("ui.components.directorypicker.notResponding.title")}</strong>
                <div>{t("ui.components.directorypicker.notResponding.body")}</div>
            </div>}
            {!error && !notResponding && listing === null && <Loading />}

            {listing && (
                <>
                    <div className="directory-roots">
                        {listing.roots.map((root) => (
                            <button
                                type="button"
                                className="btn sm"
                                key={root.path}
                                onClick={() => void load(root.path)}
                            >
                                {root.name}
                            </button>
                        ))}
                    </div>
                    <div className="directory-list">
                        {listing.parent && (
                            <button type="button" className="directory-up" onClick={() => void load(listing.parent)}>
                                <Icon name="arrowUp" size={16} /> <span>{t("ui.components.directorypicker.up.one.level")}</span>
                            </button>
                        )}
                        {listing.directories.map((directory) => (
                            <button
                                type="button"
                                key={directory.path}
                                onClick={() => void load(directory.path)}
                            >
                                <Icon name="folder" size={15} /> <span>{directory.name}</span>
                            </button>
                        ))}
                        {listing.directories.length === 0 && !listing.parent && (
                            <p className="muted">{t("ui.components.directorypicker.no.subfolders")}</p>
                        )}
                    </div>
                    <div className="modal-footer">
                        <button type="button" className="btn" onClick={close}>
                            {t("ui.components.directorypicker.cancel")}</button>
                        <button
                            type="button"
                            className="btn primary"
							onClick={() => {
								cancelLoad();
								onSelect(listing.current);
							}}
                        >
                            {t("ui.components.directorypicker.select.this.folder")}</button>
                    </div>
                </>
            )}
        </Modal>
    );
}
