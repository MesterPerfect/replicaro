package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	_ "modernc.org/sqlite"
)

const maxReadConnections = 4

var openedDatabasePaths sync.Map

func Open(path string) (*sql.DB, error) {
	if err := preflightExistingDatabase(path); err != nil {
		return nil, err
	}
	return openSQLiteWriter(path)
}

func openSQLiteWriter(path string) (*sql.DB, error) {
	// The database is opened through whatever path the app-data root
	// resolves to, symlinked folders included. There's deliberately no
	// ancestor walk and no link refusal on the database or its -wal/-shm
	// files. Those checks would only stop anyone with access to the
	// computer (other local users or software running on it) from
	// redirecting the files, which Replicaro doesn't try to defend
	// against, and they break ordinary setups such as a symlinked /home
	// or ~/.local. What matters for accidents is that a missing folder is
	// created owner-only and the files are 0600. Don't add link checks
	// back here without a product decision.
	//
	// On Windows the database lives under the application folder, so it and
	// SQLite's -wal/-shm files inherit that folder's protected DACL when
	// they're created. Nothing re-applies an ACL on open; that would only
	// matter if someone changed it, which is the same tampering case.
	if directory := filepath.Dir(path); directory != "." {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn, err := sqliteWriterDSN(absolutePath, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite serializes writes even in WAL mode. Keep one physical writer so
	// Replicaro's short control-plane transactions have deterministic ordering
	// instead of competing through SQLITE_BUSY timeouts. API reads use the
	// separate read-only pool opened by OpenReadPool. This is an architecture
	// bound, not a general tuning default; changing it requires rerunning the
	// write-ordering, busy-contention, and publication-atomicity tests.
	db.SetMaxOpenConns(1)
	// WAL permits dashboard reads while background jobs record status. A busy
	// timeout turns short write contention into bounded waiting instead of
	// intermittent "database is locked" failures.
	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if runtime.GOOS != "windows" {
		base, err := sqliteSidecarBase(path)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		for _, sidecar := range []string{path, base + "-wal", base + "-shm"} {
			if err := os.Chmod(sidecar, 0o600); err != nil && !os.IsNotExist(err) {
				_ = db.Close()
				return nil, err
			}
		}
	}
	openedDatabasePaths.Store(db, path)
	return db, nil
}

// OpenReadPool opens the bounded, query-only side of Replicaro's SQLite
// topology. Call it only after Open, migration, and startup recovery have
// established a valid database.
func OpenReadPool(path string) (*sql.DB, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn, err := sqliteReadPoolDSN(absolutePath, runtime.GOOS)
	if err != nil {
		return nil, err
	}
	readOnly, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Four readers cover the UI's small parallel request fan-out without
	// allowing expensive metadata queries to multiply CPU, memory, and WAL
	// snapshot pressure without bound. database/sql opens additional readers on
	// demand after the startup ping validates the pool. Four is an architecture
	// bound rather than a throughput knob; changes need the UI fan-out,
	// cancellation, WAL-pressure, and large File History measurements rerun.
	readOnly.SetMaxOpenConns(maxReadConnections)
	readOnly.SetMaxIdleConns(maxReadConnections)
	openedDatabasePaths.Store(readOnly, absolutePath)
	if err := readOnly.PingContext(context.Background()); err != nil {
		openedDatabasePaths.Delete(readOnly)
		_ = readOnly.Close()
		return nil, err
	}
	return readOnly, nil
}

// sqliteSidecarBase returns the path SQLite names a database's -wal and -shm
// files after. On Unix, SQLite resolves symlinks in the database path when it
// opens it, so a database file that is itself a link keeps its sidecars next
// to the link's target, not next to the link. Resolving the path the same way
// keeps our pending-WAL checks and 0600 chmods on the files SQLite really
// uses. Windows SQLite doesn't resolve links, and a path that doesn't exist
// yet has nothing to resolve, so both keep the path as given.
func sqliteSidecarBase(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return path, nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func preflightExistingDatabase(path string) error {
	// os.Stat follows links on purpose; see openSQLiteWriter. The regular-file
	// check is only there so a folder left at the database path fails with a
	// clear message instead of an SQLite error.
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return preflightMissingDatabase(path)
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database path must be a regular file")
	}
	base, err := sqliteSidecarBase(path)
	if err != nil {
		return err
	}
	walInfo, err := os.Stat(base + "-wal")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hasPendingWAL := err == nil && walInfo.Size() > 0
	if info.Size() == 0 {
		if hasPendingWAL {
			return ErrDatabaseResetRequired
		}
		return nil
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dsn := sqliteReadOnlyDSN(absolutePath, runtime.GOOS)
	readOnly, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	readOnly.SetMaxOpenConns(1)
	defer readOnly.Close()
	return checkSchemaVersion(readOnly)
}

// preflightMissingDatabase refuses to create a new database next to a
// leftover non-empty -wal file. Opening a new database there makes SQLite
// discard that WAL, and it can hold changes that were never checkpointed into
// the database file, for example after someone moved replicaro.db aside but
// not its -wal and -shm files. Nothing is created or opened here, so the
// files stay as they are until the user puts them back together.
func preflightMissingDatabase(path string) error {
	walInfo, err := os.Stat(path + "-wal")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if walInfo.Size() == 0 {
		return nil
	}
	name := filepath.Base(path)
	directory := filepath.Dir(path)
	if absolute, err := filepath.Abs(directory); err == nil {
		directory = absolute
	}
	return fmt.Errorf("%s is missing, but its %s-wal file is still in %s. It may hold recent changes. "+
		"Move %s-wal and %s-shm to the same place as %s, or put %s back, then start Replicaro again.",
		name, name, directory, name, name, name, name)
}

func sqliteReadOnlyDSN(absolutePath, goos string) string {
	sqlitePath := filepath.ToSlash(absolutePath)
	if goos == "windows" && len(sqlitePath) >= 2 && sqlitePath[1] == ':' {
		// A Windows drive path must be represented as file:///C:/... .
		// file:C:/... is parsed by SQLite as URI authority "C".
		sqlitePath = "/" + sqlitePath
	}
	return (&url.URL{
		Scheme:   "file",
		Path:     sqlitePath,
		RawQuery: "mode=ro",
	}).String()
}

// Connection-local settings must also apply after an interrupted connection is replaced.
func sqliteWriterDSN(absolutePath, goos string) (string, error) {
	parsed, err := url.Parse(sqliteReadOnlyDSN(absolutePath, goos))
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("mode", "rw") // The protected literal file was already created above.
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func sqliteReadPoolDSN(absolutePath, goos string) (string, error) {
	parsed, err := url.Parse(sqliteReadOnlyDSN(absolutePath, goos))
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	// Driver DSN pragmas run for every lazily opened physical connection.
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "query_only(1)")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// closeRows ends a rows.Next loop. Next returns false both at the end of the
// result set and when reading the next row failed (a SQLite I/O error part-way
// through, for example), and Close reports neither: the read error is only
// available from rows.Err. Callers use this instead of a bare rows.Close so a
// failed read can't pass for a shorter, complete result. That matters most
// where the list decides what gets deleted or rewritten next.
func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}
