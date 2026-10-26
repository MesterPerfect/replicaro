package database

import (
	"database/sql"
	"errors"
	"strconv"

	"github.com/local/replicaro/models"
)

var (
	ErrInvalidDashboardTimelineFilter = errors.New("invalid dashboard timeline filter")
	ErrInvalidDashboardTimelineCursor = errors.New("invalid dashboard timeline cursor")
)

// dashboardTimelineFilter selects the operations and log entries of one
// dashboard timeline tab. Kind keeps only operations of that kind;
// OtherKinds keeps only operations outside the four kinds that have their own
// tab. Logs adds the activity log.
type dashboardTimelineFilter struct {
	Kind       string
	OtherKinds bool
	Logs       bool
}

var dashboardTimelineFilters = map[string]dashboardTimelineFilter{
	"all":         {Logs: true},
	"backups":     {Kind: "backup"},
	"restores":    {Kind: "restore"},
	"checks":      {Kind: "check"},
	"maintenance": {Kind: "maintenance"},
	"other":       {OtherKinds: true, Logs: true},
}

// ListDashboardTimeline returns one page of a dashboard timeline tab, newest
// first: finished operations by their start time and activity-log entries
// (except SUPPORT diagnostics) by their timestamp. Queued and running
// operations are left out; the dashboard shows those separately. For equal
// times an operation comes before a log entry, operations by descending ID
// and log entries newest first. Entries whose time is missing or unreadable
// come first, in the same tie order, so a damaged row is shown rather than
// failing or hiding the tab. A log entry's missing (NULL) timestamp, level or
// message is returned as an empty string.
func ListDashboardTimeline(db *sql.DB, filter string, limit int, cursor string) (models.DashboardTimeline, error) {
	selected, ok := dashboardTimelineFilters[filter]
	if !ok {
		return models.DashboardTimeline{}, ErrInvalidDashboardTimelineFilter
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	beforeSeconds, beforeNanos, beforeKey, err := decodeDashboardCursor(cursor, ErrInvalidDashboardTimelineCursor)
	if err != nil {
		return models.DashboardTimeline{}, err
	}

	// sort_id breaks ties. "operation-" sorts above "log-", and log IDs are
	// zero-padded so that text order is numeric order.
	rows, err := db.Query(`
		WITH timeline_rows AS (
			SELECT 'operation' AS item_kind, id AS operation_id, 0 AS log_id,
				'operation-' || id AS sort_id, started_at AS timestamp
			FROM operations
			WHERE status NOT IN ('queued', 'running')
				AND (? = '' OR kind = ?)
				AND (? = 0 OR kind NOT IN ('backup', 'restore', 'check', 'maintenance'))

			UNION ALL

			SELECT 'log' AS item_kind, '' AS operation_id, id AS log_id,
				'log-' || printf('%020d', id) AS sort_id, timestamp
			FROM activity_log
			WHERE ? = 1 AND (level IS NULL OR level <> 'SUPPORT')
		),
		ordered_rows AS (
			SELECT timeline_rows.*, `+dashboardSortKeyColumns+`
			FROM timeline_rows
		)
		SELECT item_kind, operation_id, log_id, sort_seconds, sort_nanos, sort_id
		FROM ordered_rows
		WHERE (? = ''
			OR sort_seconds < ?
			OR (sort_seconds = ? AND (
				sort_nanos < ? OR (sort_nanos = ? AND sort_id < ?)
			)))
		ORDER BY sort_seconds DESC, sort_nanos DESC, sort_id DESC
		LIMIT ?`,
		selected.Kind, selected.Kind, selected.OtherKinds, selected.Logs,
		beforeKey, beforeSeconds, beforeSeconds, beforeNanos, beforeNanos, beforeKey, limit+1)
	if err != nil {
		return models.DashboardTimeline{}, err
	}

	type pageRow struct {
		kind, operationID string
		logID             int
		seconds           int64
		nanos             int
		key               string
	}
	page := make([]pageRow, 0, limit+1)
	for rows.Next() {
		var row pageRow
		if err := rows.Scan(&row.kind, &row.operationID, &row.logID, &row.seconds, &row.nanos, &row.key); err != nil {
			_ = rows.Close()
			return models.DashboardTimeline{}, err
		}
		page = append(page, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return models.DashboardTimeline{}, err
	}
	// The rows themselves are read with further queries, which need this
	// connection back first.
	if err := rows.Close(); err != nil {
		return models.DashboardTimeline{}, err
	}

	timeline := models.DashboardTimeline{Items: make([]models.DashboardTimelineItem, 0, min(len(page), limit))}
	if len(page) > limit {
		last := page[limit-1]
		page = page[:limit]
		timeline.HasMore = true
		timeline.NextCursor = encodeDashboardCursor(last.seconds, last.nanos, last.key)
	}

	// Operations and log entries are read straight from their tables, so they
	// come out exactly as /api/operations and /api/logs return them.
	var operationIDs []any
	var logIDs []any
	for _, row := range page {
		if row.kind == "operation" {
			operationIDs = append(operationIDs, row.operationID)
		} else {
			logIDs = append(logIDs, row.logID)
		}
	}
	operations := map[string]models.Operation{}
	if len(operationIDs) > 0 {
		rows, err := db.Query(`SELECT `+operationColumns+` FROM operations WHERE id IN (`+makePlaceholders(len(operationIDs))+`)`, operationIDs...)
		if err != nil {
			return models.DashboardTimeline{}, err
		}
		for rows.Next() {
			operation, err := scanOperation(rows.Scan)
			if err != nil {
				_ = rows.Close()
				return models.DashboardTimeline{}, err
			}
			operations[operation.ID] = operation
		}
		if err := closeRows(rows); err != nil {
			return models.DashboardTimeline{}, err
		}
	}
	entries := map[int]models.ActivityEntry{}
	if len(logIDs) > 0 {
		rows, err := db.Query(`SELECT id, timestamp, level, message FROM activity_log WHERE id IN (`+makePlaceholders(len(logIDs))+`)`, logIDs...)
		if err != nil {
			return models.DashboardTimeline{}, err
		}
		for rows.Next() {
			// The columns are scanned as they are, not through COALESCE in SQL,
			// so a time comes out in the same form /api/logs gives it.
			var entry models.ActivityEntry
			var timestamp, level, message sql.NullString
			if err := rows.Scan(&entry.ID, &timestamp, &level, &message); err != nil {
				_ = rows.Close()
				return models.DashboardTimeline{}, err
			}
			entry.Timestamp, entry.Level, entry.Message = timestamp.String, level.String, message.String
			entries[entry.ID] = entry
		}
		if err := closeRows(rows); err != nil {
			return models.DashboardTimeline{}, err
		}
	}

	// A row deleted since the page was read (log retention, or clearing the
	// activity log) is left out.
	for _, row := range page {
		if row.kind == "operation" {
			operation, ok := operations[row.operationID]
			if !ok {
				continue
			}
			operation.Steps, err = ListOperationSteps(db, operation.ID)
			if err != nil {
				return models.DashboardTimeline{}, err
			}
			timeline.Items = append(timeline.Items, models.DashboardTimelineItem{
				ID: "operation-" + operation.ID, Kind: "operation", Operation: &operation,
			})
		} else if entry, ok := entries[row.logID]; ok {
			timeline.Items = append(timeline.Items, models.DashboardTimelineItem{
				ID: "log-" + strconv.Itoa(entry.ID), Kind: "log", Log: &entry,
			})
		}
	}
	return timeline, nil
}
