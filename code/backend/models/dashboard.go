package models

type DashboardStats struct {
	RepositoryCount int    `json:"repositoryCount"`
	JobCount        int    `json:"jobCount"`
	EnabledJobs     int    `json:"enabledJobs"`
	SuccessfulRuns  int    `json:"successfulRuns"`
	WarningRuns     int    `json:"warningRuns"`
	FailedRuns      int    `json:"failedRuns"`
	LastBackup      string `json:"lastBackup"`
}

// DashboardIssueKopiaPolicyStuck is the kind of the issue a Kopia vault gets
// while an earlier policy process has kept its fence for hours; its title is
// the vault's name.
const DashboardIssueKopiaPolicyStuck = "kopia_policy_stuck"

type DashboardIssue struct {
	ID              string `json:"id"`
	Timestamp       string `json:"timestamp"`
	Kind            string `json:"kind"`
	IsNew           bool   `json:"isNew"`
	OperationKind   string `json:"operationKind,omitempty"`
	OperationID     string `json:"operationId,omitempty"`
	Severity        string `json:"severity"`
	Status          string `json:"status,omitempty"`
	IssueKind       string `json:"issueKind,omitempty"`
	Level           string `json:"level,omitempty"`
	StartedAt       string `json:"startedAt,omitempty"`
	FinishedAt      string `json:"finishedAt,omitempty"`
	Title           string `json:"title"`
	OutputAvailable bool   `json:"outputAvailable"`
}

type DashboardIssues struct {
	Items      []DashboardIssue `json:"items"`
	HasMore    bool             `json:"hasMore"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

// DashboardTimelineItem is one entry of the dashboard timeline: a finished
// operation (Kind "operation") or an activity-log entry (Kind "log"). ID is
// "operation-<id>" or "log-<id>", the same IDs the Issues feed uses.
type DashboardTimelineItem struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Operation *Operation     `json:"operation,omitempty"`
	Log       *ActivityEntry `json:"log,omitempty"`
}

type DashboardTimeline struct {
	Items      []DashboardTimelineItem `json:"items"`
	HasMore    bool                    `json:"hasMore"`
	NextCursor string                  `json:"nextCursor,omitempty"`
}
