package api

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/local/replicaro/database"
	"github.com/local/replicaro/locale"
	"github.com/local/replicaro/models"
	"github.com/local/replicaro/notifications"
)

var getNotificationSettings = database.GetSettings

func prepareOperationNotification(db *sql.DB, operationID, kind, title, status string, selectedItemsCount ...int) func() {
	return notifications.PrepareOperation(db, operationID, status, getNotificationSettings, func(settings models.Settings) notifications.Event {
		event := notifications.Event{
			Event:       kind,
			Status:      status,
			Success:     status == "success",
			Title:       title,
			OperationID: operationID,
			Locale:      locale.Effective(settings.Language),
		}
		switch kind {
		case "backup":
			if name, ok := strings.CutPrefix(title, "Backup: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.backup", name
			}
		case "check":
			if name, ok := strings.CutPrefix(title, "Check: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.check", name
			}
		case "delete":
			if name, ok := strings.CutPrefix(title, "Delete snapshot: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.deleteSnapshot", name
			}
		case database.JobDeletionKind:
			if name, ok := strings.CutPrefix(title, "Delete job: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.deleteJob", name
			}
		case database.VaultPasswordChangeKind:
			if name, ok := strings.CutPrefix(title, "Change vault password: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.changeVaultPassword", name
			}
		case database.VaultSettingsKind:
			if name, ok := strings.CutPrefix(title, "Save vault settings: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.saveVaultSettings", name
			}
		case database.VaultRemovalKind:
			if name, ok := strings.CutPrefix(title, "Remove vault: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.removeVault", name
			}
		case "restore":
			// File History supplies the count explicitly. The operation title and
			// native results stay unchanged; only notification prose is localized.
			if len(selectedItemsCount) == 1 {
				event.TaskKey, event.TaskName = "notifications.task.restoreSelectedItems", strconv.Itoa(selectedItemsCount[0])
			} else if name, ok := strings.CutPrefix(title, "Restore snapshot: "); ok {
				event.TaskKey, event.TaskName = "notifications.task.restoreSnapshot", name
			}
		}
		return event
	})
}
