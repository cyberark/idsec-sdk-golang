package models

// IdsecPCloudAccountComplianceAction represents an action that was performed on an account.
type IdsecPCloudAccountComplianceAction struct {
	Username string `json:"username" mapstructure:"username" desc:"The user who performed the action" flag:"username"`
	Type     string `json:"type" mapstructure:"type" desc:"The type of action that was performed" flag:"type"`
	Time     string `json:"time" mapstructure:"time" desc:"The date and time when the action took place (UTC)" flag:"time"`
}

// IdsecPCloudAccountComplianceChange represents the compliance details of the account's change operation.
type IdsecPCloudAccountComplianceChange struct {
	Compliant                           string `json:"compliant" mapstructure:"compliant" desc:"The compliance status of the change operation" flag:"compliant"`
	PolicyInterval                      int    `json:"policy_interval" mapstructure:"policy_interval" desc:"The interval defined by the policy for the change operation" flag:"policy-interval"`
	LastSuccess                         string `json:"last_success" mapstructure:"last_success" desc:"The date and time of the last successful change operation" flag:"last-success"`
	NextSchedule                        string `json:"next_schedule" mapstructure:"next_schedule" desc:"The date and time of the next scheduled change operation" flag:"next-schedule"`
	RetryCount                          int    `json:"retry_count" mapstructure:"retry_count" desc:"The number of retries for the change operation" flag:"retry-count"`
	DaysSinceLastSuccess                int    `json:"days_since_last_success" mapstructure:"days_since_last_success" desc:"The number of days since the last successful change operation" flag:"days-since-last-success"`
	SecondsSinceLastSuccess             int    `json:"seconds_since_last_success" mapstructure:"seconds_since_last_success" desc:"The number of seconds since the last successful change operation" flag:"seconds-since-last-success"`
	Username                            string `json:"username" mapstructure:"username" desc:"The user associated with the change operation" flag:"username"`
	ActionEnabled                       bool   `json:"action_enabled" mapstructure:"action_enabled" desc:"Whether the change action is enabled" flag:"action-enabled"`
	ActionDisabledReason                string `json:"action_disabled_reason" mapstructure:"action_disabled_reason" desc:"The reason the change action is disabled" flag:"action-disabled-reason"`
	ActionEnabledVault                  bool   `json:"action_enabled_vault" mapstructure:"action_enabled_vault" desc:"Whether the change action is enabled in the vault" flag:"action-enabled-vault"`
	AllowSpecifySecret                  bool   `json:"allow_specify_secret" mapstructure:"allow_specify_secret" desc:"Whether specifying the secret is allowed for the change operation" flag:"allow-specify-secret"`
	EnforcePasswordPolicyOnManualChange bool   `json:"enforce_password_policy_on_manual_change" mapstructure:"enforce_password_policy_on_manual_change" desc:"Whether the password policy is enforced on manual change" flag:"enforce-password-policy-on-manual-change"`
}

// IdsecPCloudAccountComplianceVerify represents the compliance details of the account's verify operation.
type IdsecPCloudAccountComplianceVerify struct {
	Compliant               string `json:"compliant" mapstructure:"compliant" desc:"The compliance status of the verify operation" flag:"compliant"`
	PolicyInterval          int    `json:"policy_interval" mapstructure:"policy_interval" desc:"The interval defined by the policy for the verify operation" flag:"policy-interval"`
	LastSuccess             string `json:"last_success" mapstructure:"last_success" desc:"The date and time of the last successful verify operation" flag:"last-success"`
	NextSchedule            string `json:"next_schedule" mapstructure:"next_schedule" desc:"The date and time of the next scheduled verify operation" flag:"next-schedule"`
	RetryCount              int    `json:"retry_count" mapstructure:"retry_count" desc:"The number of retries for the verify operation" flag:"retry-count"`
	DaysSinceLastSuccess    int    `json:"days_since_last_success" mapstructure:"days_since_last_success" desc:"The number of days since the last successful verify operation" flag:"days-since-last-success"`
	SecondsSinceLastSuccess int    `json:"seconds_since_last_success" mapstructure:"seconds_since_last_success" desc:"The number of seconds since the last successful verify operation" flag:"seconds-since-last-success"`
	Username                string `json:"username" mapstructure:"username" desc:"The user associated with the verify operation" flag:"username"`
	ActionEnabled           bool   `json:"action_enabled" mapstructure:"action_enabled" desc:"Whether the verify action is enabled" flag:"action-enabled"`
	ActionDisabledReason    string `json:"action_disabled_reason" mapstructure:"action_disabled_reason" desc:"The reason the verify action is disabled" flag:"action-disabled-reason"`
}

// IdsecPCloudAccountComplianceReconcile represents the compliance details of the account's reconcile operation.
type IdsecPCloudAccountComplianceReconcile struct {
	ActionEnabled        bool   `json:"action_enabled" mapstructure:"action_enabled" desc:"Whether the reconcile action is enabled" flag:"action-enabled"`
	ActionDisabledReason string `json:"action_disabled_reason" mapstructure:"action_disabled_reason" desc:"The reason the reconcile action is disabled" flag:"action-disabled-reason"`
	NextSchedule         string `json:"next_schedule" mapstructure:"next_schedule" desc:"The date and time of the next scheduled reconcile operation" flag:"next-schedule"`
	RetryCount           int    `json:"retry_count" mapstructure:"retry_count" desc:"The number of retries for the reconcile operation" flag:"retry-count"`
}

// IdsecPCloudAccountComplianceDelete represents the compliance details of the account's delete operation.
type IdsecPCloudAccountComplianceDelete struct {
	NextSchedule string `json:"next_schedule" mapstructure:"next_schedule" desc:"The date and time of the next scheduled delete operation" flag:"next-schedule"`
	Username     string `json:"username" mapstructure:"username" desc:"The user associated with the delete operation" flag:"username"`
	RetryCount   int    `json:"retry_count" mapstructure:"retry_count" desc:"The number of retries for the delete operation" flag:"retry-count"`
}

// IdsecPCloudAccountComplianceInfo represents the compliance info of an account.
type IdsecPCloudAccountComplianceInfo struct {
	AccountState            string                                 `json:"account_state" mapstructure:"account_state" desc:"The current state of the account" flag:"account-state"`
	DisableReason           string                                 `json:"disable_reason" mapstructure:"disable_reason" desc:"The reason the account is disabled" flag:"disable-reason"`
	ResumeActionEnabled     *bool                                  `json:"resume_action_enabled" mapstructure:"resume_action_enabled" desc:"Whether the resume action is enabled" flag:"resume-action-enabled"`
	PlatformID              string                                 `json:"platform_id" mapstructure:"platform_id" desc:"The ID of the platform assigned to the account" flag:"platform-id"`
	AccountGroupID          string                                 `json:"account_group_id" mapstructure:"account_group_id" desc:"The ID of the account group" flag:"account-group-id"`
	AccountGroupName        string                                 `json:"account_group_name" mapstructure:"account_group_name" desc:"The name of the account group" flag:"account-group-name"`
	GroupPlatformID         string                                 `json:"group_platform_id" mapstructure:"group_platform_id" desc:"The ID of the group platform" flag:"group-platform-id"`
	ManagementType          string                                 `json:"management_type" mapstructure:"management_type" desc:"The management type of the account" flag:"management-type"`
	LastMessages            []interface{}                          `json:"last_messages" mapstructure:"last_messages" desc:"The last messages related to the account" flag:"last-messages"`
	ActionInProgress        interface{}                            `json:"action_in_progress" mapstructure:"action_in_progress" desc:"The action currently in progress on the account" flag:"action-in-progress"`
	LastAction              *IdsecPCloudAccountComplianceAction    `json:"last_action" mapstructure:"last_action" desc:"The last action performed on the account" flag:"last-action"`
	LastVerifyAction        *IdsecPCloudAccountComplianceAction    `json:"last_verify_action" mapstructure:"last_verify_action" desc:"The last verify action performed on the account" flag:"last-verify-action"`
	Change                  *IdsecPCloudAccountComplianceChange    `json:"change" mapstructure:"change" desc:"The compliance details of the account's change operation" flag:"change"`
	Verify                  *IdsecPCloudAccountComplianceVerify    `json:"verify" mapstructure:"verify" desc:"The compliance details of the account's verify operation" flag:"verify"`
	Reconcile               *IdsecPCloudAccountComplianceReconcile `json:"reconcile" mapstructure:"reconcile" desc:"The compliance details of the account's reconcile operation" flag:"reconcile"`
	Delete                  *IdsecPCloudAccountComplianceDelete    `json:"delete" mapstructure:"delete" desc:"The compliance details of the account's delete operation" flag:"delete"`
	ActiveJob               interface{}                            `json:"active_job" mapstructure:"active_job" desc:"The active job running on the account" flag:"active-job"`
	IsActiveWorkflowSession bool                                   `json:"is_active_workflow_session" mapstructure:"is_active_workflow_session" desc:"Whether there is an active workflow session for the account" flag:"is-active-workflow-session"`
	ReleaseAccountEnabled   bool                                   `json:"release_account_enabled" mapstructure:"release_account_enabled" desc:"Whether releasing the account is enabled" flag:"release-account-enabled"`
	UnlockAccountEnabled    bool                                   `json:"unlock_account_enabled" mapstructure:"unlock_account_enabled" desc:"Whether unlocking the account is enabled" flag:"unlock-account-enabled"`
	CreatedAt               string                                 `json:"created_at" mapstructure:"created_at" desc:"The date and time the account was created (UTC)" flag:"created-at"`
}

// IdsecPCloudBulkAccountComplianceInfoResult represents the compliance info result of a single account in a bulk operation.
type IdsecPCloudBulkAccountComplianceInfoResult struct {
	AccountID      string                            `json:"account_id" mapstructure:"account_id" desc:"The ID of the account" flag:"account-id"`
	ComplianceInfo *IdsecPCloudAccountComplianceInfo `json:"compliance_info" mapstructure:"compliance_info" desc:"The compliance info of the account, if the retrieval succeeded" flag:"compliance-info"`
	Error          string                            `json:"error,omitempty" mapstructure:"error,omitempty" desc:"The error that occurred while retrieving the account's compliance info, if any" flag:"error"`
}
