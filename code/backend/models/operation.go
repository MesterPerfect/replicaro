package models

type Operation struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Status       string          `json:"status"` // queued, running, success, completed_with_issues, reconnect_required, failed, partial, interrupted, skipped
	Title        string          `json:"title"`
	JobID        string          `json:"jobId"`
	RepositoryID string          `json:"repositoryId"`
	Engine       string          `json:"engine"`
	StartedAt    string          `json:"startedAt"`
	FinishedAt   string          `json:"finishedAt"`
	IssueKind    string          `json:"issueKind,omitempty"` // "" or OperationIssueLockedFiles, only on a completed_with_issues backup
	Steps        []OperationStep `json:"steps,omitempty"`
}

// OperationIssueLockedFiles marks a completed_with_issues backup whose only
// problems were source files another program held locked. It is a qualifier
// on that status rather than a status of its own: dashboards, health,
// retention and webhook consumers keep matching "completed_with_issues"
// exactly as before, and an older build reading the same database simply
// shows the plain result.
const OperationIssueLockedFiles = "locked_files"

type OperationStep struct {
	ID          string `json:"id"`
	OperationID string `json:"operationId"`
	Domain      string `json:"domain"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	StartedAt   string `json:"startedAt"`
	FinishedAt  string `json:"finishedAt"`
}
