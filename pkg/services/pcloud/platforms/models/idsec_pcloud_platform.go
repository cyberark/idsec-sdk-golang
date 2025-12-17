package models

// Platform type constants.
const (
	PlatformTypeRegular          = "regular"
	PlatformTypeGroup            = "group"
	PlatformTypeRotationalGroups = "rotationalgroup"
	PlatformTypeDependent        = "dependent"
)

// IdsecPCloudPlatformGeneralDetails represents the general details of a platform.
type IdsecPCloudPlatformGeneralDetails struct {
	ID             string `json:"id" mapstructure:"id" desc:"ID of the platform" flag:"id"`
	Name           string `json:"name" mapstructure:"name" desc:"Name of the platform" flag:"name"`
	SystemType     string `json:"system_type" mapstructure:"system_type" desc:"System type of the platform" flag:"system-type"`
	Active         bool   `json:"active" mapstructure:"active" desc:"Whether this platform is active or not" flag:"active"`
	Description    string `json:"description" mapstructure:"description" desc:"Description about the platform" flag:"description"`
	PlatformBaseID string `json:"platform_base_id" mapstructure:"platform_base_id" desc:"Base ID of the platform if inherits from another one" flag:"platform-base-id"`
	PlatformType   string `json:"platform_type" mapstructure:"platform_type" desc:"Type of the platform" flag:"platform-type" choices:"regular,group,rotationalgroup,dependent"`
}

// IdsecPCloudPlatformProperty represents a platform property.
type IdsecPCloudPlatformProperty struct {
	Name        string `json:"name" mapstructure:"name" desc:"Property name" flag:"name"`
	DisplayName string `json:"display_name" mapstructure:"display_name" desc:"Property display name" flag:"display-name"`
}

// IdsecPCloudPlatformProperties represents the platform properties.
type IdsecPCloudPlatformProperties struct {
	Required []IdsecPCloudPlatformProperty `json:"required" mapstructure:"required" desc:"Required platform properties" flag:"required"`
	Optional []IdsecPCloudPlatformProperty `json:"optional" mapstructure:"optional" desc:"Optional platform properties" flag:"optional"`
}

// IdsecPCloudCredentialsManagement represents the credentials management configuration of a platform.
type IdsecPCloudCredentialsManagement struct {
	AllowedSafes                          string `json:"allowed_safes" mapstructure:"allowed_safes" desc:"Which safes regex are allowed for credentials management" flag:"allowed-safes"`
	AllowManualChange                     bool   `json:"allow_manual_change" mapstructure:"allow_manual_change" desc:"Whether manual change of credentials is allowed" flag:"allow-manual-change"`
	PerformPeriodicChange                 bool   `json:"perform_periodic_change" mapstructure:"perform_periodic_change" desc:"Whether to perform periodic change of credentials" flag:"perform-periodic-change"`
	RequirePasswordChangeEveryXDays       int    `json:"require_password_change_every_x_days" mapstructure:"require_password_change_every_x_days" desc:"Every how much time to perfrom the periodic change" flag:"require-password-change-every-x-days"`
	AllowManualVerification               bool   `json:"allow_manual_verification" mapstructure:"allow_manual_verification" desc:"Allow manual verification of credentials" flag:"allow-manual-verification"`
	PerformPeriodicVerification           bool   `json:"perform_periodic_verification" mapstructure:"perform_periodic_verification" desc:"Whether to perform periodic verification of credentials" flag:"perform-periodic-verification"`
	RequirePasswordVerificationEveryXDays int    `json:"require_password_verification_every_x_days" mapstructure:"require_password_verification_every_x_days" desc:"Every how much time to perform periodic verification" flag:"require-password-verification-every-x-days"`
	AllowManualReconciliation             bool   `json:"allow_manual_reconciliation" mapstructure:"allow_manual_reconciliation" desc:"Allow manual reconciliation of credentials" flag:"allow-manual-reconciliation"`
	AutomaticReconcileWhenUnsynched       bool   `json:"automatic_reconcile_when_unsynched" mapstructure:"automatic_reconcile_when_unsynched" desc:"Reconcile credentials automatically when unsynced" flag:"automatic-reconcile-when-unsynched"`
}

// IdsecPCloudSessionManagement represents the session management configuration of a platform.
type IdsecPCloudSessionManagement struct {
	RequirePrivilegedSessionMonitoringAndIsolation bool   `json:"require_privileged_session_monitoring_and_isolation" mapstructure:"require_privileged_session_monitoring_and_isolation" desc:"Whether sessions require PSM isolation and monitoring" flag:"require-privileged-session-monitoring-and-isolation"`
	RecordAndSaveSessionActivity                   bool   `json:"record_and_save_session_activity" mapstructure:"record_and_save_session_activity" desc:"Whether to record and save session activity" flag:"record-and-save-session-activity"`
	PSMServerID                                    string `json:"psm_server_id" mapstructure:"psm_server_id" desc:"ID of the psm server installed" flag:"psm-server-id"`
}

// IdsecPCloudPrivilegedAccessWorkflows represents the privileged access workflows configuration of a platform.
type IdsecPCloudPrivilegedAccessWorkflows struct {
	RequireDualControlPasswordAccessApproval bool `json:"require_dual_control_password_access_approval" mapstructure:"require_dual_control_password_access_approval" desc:"Whether dual control is required for access" flag:"require-dual-control-password-access-approval"`
	EnforceCheckinCheckoutExclusiveAccess    bool `json:"enforce_checkin_checkout_exclusive_access" mapstructure:"enforce_checkin_checkout_exclusive_access" desc:"Whether to enforce exclusive access" flag:"enforce-checkin-checkout-exclusive-access"`
	EnforceOnetimePasswordAccess             bool `json:"enforce_onetime_password_access" mapstructure:"enforce_onetime_password_access" desc:"Whether to enforce one time password access" flag:"enforce-onetime-password-access"`
}

// IdsecPCloudPlatform represents the full properties of a platform.
type IdsecPCloudPlatform struct {
	General                   IdsecPCloudPlatformGeneralDetails    `json:"general" mapstructure:"general" desc:"General platform settings" flag:"general"`
	Properties                IdsecPCloudPlatformProperties        `json:"properties" mapstructure:"properties" desc:"Platform properties" flag:"properties"`
	LinkedAccounts            []IdsecPCloudPlatformProperty        `json:"linked_accounts" mapstructure:"linked_accounts" desc:"Platform linked accounts" flag:"linked-accounts"`
	CredentialsManagement     IdsecPCloudCredentialsManagement     `json:"credentials_management" mapstructure:"credentials_management" desc:"Platform credentials management properties" flag:"credentials-management"`
	SessionManagement         IdsecPCloudSessionManagement         `json:"session_management" mapstructure:"session_management" desc:"Platform session management properties" flag:"session-management"`
	PrivilegedAccessWorkflows IdsecPCloudPrivilegedAccessWorkflows `json:"privileged_access_workflows" mapstructure:"privileged_access_workflows" desc:"Platform privileged access workflows properties" flag:"privileged-access-workflows"`
}
