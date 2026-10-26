package api

type SaveSettingsRequest struct {
	DefaultEngine                string  `json:"defaultEngine"`
	LogRetentionDays             int     `json:"logRetentionDays"`
	Theme                        string  `json:"theme"`
	Language                     *string `json:"language"`
	WebhookURL                   string  `json:"webhookUrl"`
	NotifyWindowsOnSuccess       bool    `json:"notifyWindowsOnSuccess"`
	NotifyWindowsOnFailure       bool    `json:"notifyWindowsOnFailure"`
	NativeNotificationsOnSuccess bool    `json:"nativeNotificationsOnSuccess"`
	NativeNotificationsOnFailure bool    `json:"nativeNotificationsOnFailure"`
	NotifyWebhookOnSuccess       bool    `json:"notifyWebhookOnSuccess"`
	NotifyWebhookOnFailure       bool    `json:"notifyWebhookOnFailure"`

	StartWithWindows             bool `json:"startWithWindows"`
	StartAtLogin                 bool `json:"startAtLogin"`
	MaxConcurrentJobRuns         int  `json:"maxConcurrentJobRuns"`
	DisableAutomaticUpdateChecks bool `json:"disableAutomaticUpdateChecks"`

	// Accepted and ignored. Nothing acts on these preferences, but an older
	// page or client still sends them with the rest of its settings document,
	// and the strict decoder would otherwise refuse the whole save.
	IgnoredAutoStart      bool `json:"autoStart"`
	IgnoredMinimizeToTray bool `json:"minimizeToTray"`
}
