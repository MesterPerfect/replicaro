package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// RcloneVaultConfigOwnerIDs returns existing repository IDs and exact active
// workflow-owned repository IDs. It derives only from existing durable state.
// Startup uses the same set for the vault rclone configs and the engine
// caches it keeps.
func RcloneVaultConfigOwnerIDs(db *sql.DB) (map[string]bool, error) {
	result := map[string]bool{}
	rows, err := db.Query(`SELECT id FROM repositories
		UNION SELECT id FROM repository_creation_intents`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		result[id] = true
	}
	// Startup reconcile deletes the local rclone config of every vault missing
	// from this set, so a read error part-way through must fail the whole call.
	// rows.Next only reports it through rows.Err; returning the partial set
	// would delete a live vault's OAuth sign-in.
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := addConnectionIntentRepositoryIDs(db, result); err != nil {
		return nil, err
	}
	return result, nil
}

// RepositoryIDOwnedOutsideCreation reports whether a saved vault or an
// unfinished connection uses id. These are the owners
// RcloneVaultConfigOwnerIDs counts besides creations, so a pending creation
// that shares its ID with one of them must leave the local engine config,
// rclone config and cache under that ID alone.
func RepositoryIDOwnedOutsideCreation(db *sql.DB, id string) (bool, error) {
	var saved bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM repositories WHERE id = ?)`, id).Scan(&saved); err != nil {
		return false, err
	}
	if saved {
		return true, nil
	}
	connections := map[string]bool{}
	if err := addConnectionIntentRepositoryIDs(db, connections); err != nil {
		return false, err
	}
	return connections[id], nil
}

// addConnectionIntentRepositoryIDs adds the vault ID of every unfinished
// connection. A payload that can't be read fails the whole call, so no caller
// treats that connection's files as unowned.
func addConnectionIntentRepositoryIDs(db *sql.DB, result map[string]bool) error {
	rows, err := db.Query(`SELECT payload_json FROM repository_connection_intents`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			_ = rows.Close()
			return err
		}
		var value struct {
			Repository struct {
				ID string `json:"id"`
			} `json:"repository"`
		}
		if err := json.Unmarshal([]byte(payload), &value); err != nil || value.Repository.ID == "" {
			_ = rows.Close()
			return fmt.Errorf("decode active repository connection config ownership")
		}
		result[value.Repository.ID] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}
