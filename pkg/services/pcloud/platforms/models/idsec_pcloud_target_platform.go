package models

// IdsecPCloudTPPrivilegedAccessWorkflowsActiveException represents the active exception configuration for workflows.
type IdsecPCloudTPPrivilegedAccessWorkflowsActiveException struct {
	IsActive      bool `json:"is_active" mapstructure:"is_active" desc:"Whether workflow is active" flag:"is-active"`
	IsAnException bool `json:"is_an_exception" mapstructure:"is_an_exception" desc:"Whether workflow is an exception" flag:"is-an-exception"`
}

// IdsecPCloudTPPrivilegedAccessWorkflows represents the privileged access workflows configuration of a target platform.
type IdsecPCloudTPPrivilegedAccessWorkflows struct {
	RequireDualControlPasswordAccessApproval IdsecPCloudTPPrivilegedAccessWorkflowsActiveException `json:"require_dual_control_password_access_approval" mapstructure:"require_dual_control_password_access_approval" desc:"Dual control workflow details" flag:"require-dual-control-password-access-approval"`
	EnforceCheckinCheckoutExclusiveAccess    IdsecPCloudTPPrivilegedAccessWorkflowsActiveException `json:"enforce_checkin_checkout_exclusive_access" mapstructure:"enforce_checkin_checkout_exclusive_access" desc:"Checkin checkout workflow details" flag:"enforce-checkin-checkout-exclusive-access"`
	EnforceOnetimePasswordAccess             IdsecPCloudTPPrivilegedAccessWorkflowsActiveException `json:"enforce_onetime_password_access" mapstructure:"enforce_onetime_password_access" desc:"One time password workflow details" flag:"enforce-onetime-password-access"`
	RequireUsersToSpecifyReasonForAccess     IdsecPCloudTPPrivilegedAccessWorkflowsActiveException `json:"require_users_to_specify_reason_for_access" mapstructure:"require_users_to_specify_reason_for_access" desc:"Specify reason workflow details" flag:"require-users-to-specify-reason-for-access"`
}

// IdsecPCloudTPCredentialsManagementVerificationChangePolicy represents the verification or change policy configuration.
type IdsecPCloudTPCredentialsManagementVerificationChangePolicy struct {
	PerformAutomatic                       bool `json:"perform_automatic" mapstructure:"perform_automatic" desc:"Indicates whether accounts related to this platform will be changed automatically" flag:"perform-automatic"`
	RequirePasswordEveryXDays              int  `json:"require_password_every_x_days" mapstructure:"require_password_every_x_days" desc:"The number of days between each periodic change" flag:"require-password-every-x-days"`
	AutoOnAdd                              bool `json:"auto_on_add" mapstructure:"auto_on_add" desc:"Indicates whether accounts related to this platform will be changed after being added" flag:"auto-on-add"`
	IsRequirePasswordEveryXDaysAnException bool `json:"is_require_password_every_x_days_an_exception" mapstructure:"is_require_password_every_x_days_an_exception" desc:"Indicates whether the number of days between each periodic change is an exception to the master policy" flag:"is-require-password-every-x-days-an-exception"`
	AllowManual                            bool `json:"allow_manual" mapstructure:"allow_manual" desc:"Indicates whether an immediate change process can be initiated manually" flag:"allow-manual"`
}

// IdsecPCloudTPCredentialsManagementReconcilePolicy represents the reconcile policy configuration.
type IdsecPCloudTPCredentialsManagementReconcilePolicy struct {
	AutomaticReconcileWhenUnsynced bool `json:"automatic_reconcile_when_unsynced" mapstructure:"automatic_reconcile_when_unsynced" desc:"Indicates whether or not passwords will be reconciled automatically after the CPM detects a password on a remote machine that is not synchronized with its corresponding password in the Server" flag:"automatic-reconcile-when-unsynced"`
	AllowManual                    bool `json:"allow_manual" mapstructure:"allow_manual" desc:"Indicates whether an immediate reconcile process can be initiated manually" flag:"allow-manual"`
}

// IdsecPCloudTPCredentialsManagementSecretUpdateConfiguration represents the secret update configuration.
type IdsecPCloudTPCredentialsManagementSecretUpdateConfiguration struct {
	ChangePasswordInResetMode bool `json:"change_password_in_reset_mode" mapstructure:"change_password_in_reset_mode" desc:"Defines whether or not password changes will be performed via reset mode using the reconciliation account. This is useful in cases where the password policy prevents the user from changing his own password or when a password minimal age restriction is applied" flag:"change-password-in-reset-mode"`
}

// IdsecPCloudTPCredentialsManagementPolicy represents the credentials management policy configuration of a target platform.
type IdsecPCloudTPCredentialsManagementPolicy struct {
	Verification              IdsecPCloudTPCredentialsManagementVerificationChangePolicy  `json:"verification" mapstructure:"verification" desc:"Verification policy" flag:"verification"`
	Change                    IdsecPCloudTPCredentialsManagementVerificationChangePolicy  `json:"change" mapstructure:"change" desc:"Change policy" flag:"change"`
	Reconcile                 IdsecPCloudTPCredentialsManagementReconcilePolicy           `json:"reconcile" mapstructure:"reconcile" desc:"Reconcile policy" flag:"reconcile"`
	SecretUpdateConfiguration IdsecPCloudTPCredentialsManagementSecretUpdateConfiguration `json:"secret_update_configuration" mapstructure:"secret_update_configuration" desc:"Secret update configuration" flag:"secret-update-configuration"`
}

// IdsecPCloudTPPrivilegedSessionManagement represents the privileged session management configuration of a target platform.
type IdsecPCloudTPPrivilegedSessionManagement struct {
	PSMServerID   string `json:"psm_server_id" mapstructure:"psm_server_id" desc:"PSM server id" flag:"psm-server-id"`
	PSMServerName string `json:"psm_server_name" mapstructure:"psm_server_name" desc:"PSM server name" flag:"psm-server-name"`
}

// IdsecPCloudTargetPlatform represents the full properties of a target platform.
type IdsecPCloudTargetPlatform struct {
	ID                          int                                       `json:"id" mapstructure:"id" desc:"Unique numeric ID of the platform" flag:"id"`
	PlatformID                  string                                    `json:"platform_id" mapstructure:"platform_id" desc:"Unique string ID of the platform" flag:"platform-id"`
	Name                        string                                    `json:"name" mapstructure:"name" desc:"The display name of the platform" flag:"name"`
	Active                      bool                                      `json:"active" mapstructure:"active" desc:"Indicates whether a platform is active or inactive" flag:"active"`
	SystemType                  string                                    `json:"system_type" mapstructure:"system_type" desc:"The type of system associated with the target" flag:"system-type"`
	AllowedSafes                string                                    `json:"allowed_safes" mapstructure:"allowed_safes" desc:"Regex of safes in which accounts from this platform can be managed" flag:"allowed-safes"`
	PrivilegedAccessWorkflows   *IdsecPCloudTPPrivilegedAccessWorkflows   `json:"privileged_access_workflows" mapstructure:"privileged_access_workflows" desc:"Workflows configuration" flag:"privileged-access-workflows"`
	CredentialsManagementPolicy *IdsecPCloudTPCredentialsManagementPolicy `json:"credentials_management_policy" mapstructure:"credentials_management_policy" desc:"CPM Policy" flag:"credentials-management-policy"`
	PrivilegedSessionManagement *IdsecPCloudTPPrivilegedSessionManagement `json:"privileged_session_management" mapstructure:"privileged_session_management" desc:"PSM Management" flag:"privileged-session-management"`
}
