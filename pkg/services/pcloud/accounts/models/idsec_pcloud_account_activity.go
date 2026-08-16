package models

// IdsecPCloudAccountAuditEventCustomData represents a single key-value pair in the custom_event_data field of an audit event.
type IdsecPCloudAccountAuditEventCustomData struct {
	Title string `json:"title" mapstructure:"title" desc:"The name of the custom data field" flag:"title"`
	Value string `json:"value" mapstructure:"value" desc:"The value of the custom data field" flag:"value"`
}

// IdsecPCloudAccountActivity represents a single activity that was performed on an account.
type IdsecPCloudAccountActivity struct {
	// Existing fields for classic activities
	Alert    bool   `json:"alert,omitempty" mapstructure:"alert,omitempty" desc:"Whether the activity triggered an alert" flag:"alert"`
	Date     int    `json:"date,omitempty" mapstructure:"date,omitempty" desc:"The date and time when the activity took place (UTC)" flag:"date"`
	User     string `json:"user,omitempty" mapstructure:"user,omitempty" desc:"The user who performed the activity" flag:"user"`
	Action   string `json:"action,omitempty" mapstructure:"action,omitempty" desc:"The activity that was performed" flag:"action"`
	ActionID int    `json:"action_id,omitempty" mapstructure:"action_id,omitempty" desc:"The ID of the activity that was performed" flag:"action-id"`
	ClientID string `json:"client_id,omitempty" mapstructure:"client_id,omitempty" desc:"The ID of the CyberArk client from which the user connected and performed the activity" flag:"client-id"`
	MoreInfo string `json:"more_info,omitempty" mapstructure:"more_info,omitempty" desc:"More information about the activity" flag:"more-info"`
	Reason   string `json:"reason,omitempty" mapstructure:"reason,omitempty	" desc:"The reason given by the user for the activity" flag:"reason"`

	// New fields for audit events
	AccessMethod            interface{}                               `json:"access_method,omitempty" mapstructure:"access_method,omitempty" desc:"The access method used" flag:"access-method"`
	AccountID               string                                    `json:"account_id,omitempty" mapstructure:"account_id,omitempty" desc:"The ID of the account" flag:"account-id"`
	AccountName             string                                    `json:"account_name,omitempty" mapstructure:"account_name,omitempty" desc:"The name of the account" flag:"account-name"`
	ActionType              string                                    `json:"action_type,omitempty" mapstructure:"action_type,omitempty" desc:"The type of action" flag:"action-type"`
	ApplicationCode         interface{}                               `json:"application_code,omitempty" mapstructure:"application_code,omitempty" desc:"The application code" flag:"application-code"`
	ArrivalTimestamp        interface{}                               `json:"arrival_timestamp,omitempty" mapstructure:"arrival_timestamp,omitempty" desc:"The arrival timestamp of the event" flag:"arrival-timestamp"`
	AuditCode               string                                    `json:"audit_code,omitempty" mapstructure:"audit_code,omitempty" desc:"The audit code of the event" flag:"audit-code"`
	AuditType               string                                    `json:"audit_type,omitempty" mapstructure:"audit_type,omitempty" desc:"The audit type of the event" flag:"audit-type"`
	Checksum                interface{}                               `json:"checksum,omitempty" mapstructure:"checksum,omitempty" desc:"The checksum of the event" flag:"checksum"`
	CloudAssets             interface{}                               `json:"cloud_assets,omitempty" mapstructure:"cloud_assets,omitempty" desc:"The cloud assets involved" flag:"cloud-assets"`
	CloudIdentities         interface{}                               `json:"cloud_identities,omitempty" mapstructure:"cloud_identities,omitempty" desc:"The cloud identities involved" flag:"cloud-identities"`
	CloudProvider           interface{}                               `json:"cloud_provider,omitempty" mapstructure:"cloud_provider,omitempty" desc:"The cloud provider" flag:"cloud-provider"`
	CloudRoles              interface{}                               `json:"cloud_roles" mapstructure:"cloud_roles" desc:"The cloud roles involved" flag:"cloud-roles"`
	CloudWorkspaces         interface{}                               `json:"cloud_workspaces,omitempty" mapstructure:"cloud_workspaces,omitempty" desc:"The cloud workspaces involved" flag:"cloud-workspaces"`
	CloudWorkspacesAndRoles []interface{}                             `json:"cloud_workspaces_and_roles,omitempty" mapstructure:"cloud_workspaces_and_roles,omitempty" desc:"The cloud workspaces and roles involved" flag:"cloud-workspaces-and-roles"`
	Command                 string                                    `json:"command,omitempty" mapstructure:"command,omitempty" desc:"The command that was executed" flag:"command"`
	Component               interface{}                               `json:"component,omitempty" mapstructure:"component,omitempty" desc:"The component that generated the event" flag:"component"`
	CorrelationID           interface{}                               `json:"correlation_id,omitempty" mapstructure:"correlation_id,omitempty" desc:"The correlation ID of the event" flag:"correlation-id"`
	CustomEventData         []*IdsecPCloudAccountAuditEventCustomData `json:"custom_event_data,omitempty" mapstructure:"custom_event_data,omitempty" desc:"Additional custom data fields for the event" flag:"custom-event-data"`
	IdentityType            interface{}                               `json:"identity_type,omitempty" mapstructure:"identity_type,omitempty" desc:"The identity type" flag:"identity-type"`
	IsDR                    bool                                      `json:"is_dr,omitempty" mapstructure:"is_dr,omitempty" desc:"Whether this is a disaster-recovery event" flag:"is-dr"`
	Message                 string                                    `json:"message,omitempty" mapstructure:"message,omitempty" desc:"The event message or reason" flag:"message"`
	OriginRegion            string                                    `json:"origin_region,omitempty" mapstructure:"origin_region,omitempty" desc:"The region where the event originated" flag:"origin-region"`
	Safe                    interface{}                               `json:"safe,omitempty" mapstructure:"safe,omitempty" desc:"The safe associated with the event" flag:"safe"`
	ServiceName             interface{}                               `json:"service_name,omitempty" mapstructure:"service_name,omitempty" desc:"The service that generated the event" flag:"service-name"`
	SessionID               interface{}                               `json:"session_id,omitempty" mapstructure:"session_id,omitempty" desc:"The session ID associated with the event" flag:"session-id"`
	Source                  string                                    `json:"source,omitempty" mapstructure:"source,omitempty" desc:"The source system that generated the event" flag:"source"`
	Target                  interface{}                               `json:"target,omitempty" mapstructure:"target,omitempty" desc:"The target of the action" flag:"target"`
	TargetAccount           interface{}                               `json:"target_account,omitempty" mapstructure:"target_account,omitempty" desc:"The target account of the action" flag:"target-account"`
	TargetPlatform          interface{}                               `json:"target_platform,omitempty" mapstructure:"target_platform,omitempty" desc:"The target platform of the action" flag:"target-platform"`
	TenantID                interface{}                               `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" desc:"The tenant ID" flag:"tenant-id"`
	Timestamp               int64                                     `json:"timestamp,omitempty" mapstructure:"timestamp,omitempty" desc:"The event timestamp in milliseconds (UTC)" flag:"timestamp"`
	UserID                  string                                    `json:"user_id,omitempty" mapstructure:"user_id,omitempty" desc:"The ID of the user who performed the action" flag:"user-id"`
	Username                string                                    `json:"username,omitempty" mapstructure:"username,omitempty" desc:"The username of the user who performed the action" flag:"username"`
	UUID                    string                                    `json:"uuid,omitempty" mapstructure:"uuid,omitempty" desc:"The unique identifier of the event" flag:"uuid"`
	VaultedAccounts         interface{}                               `json:"vaulted_accounts,omitempty" mapstructure:"vaulted_accounts,omitempty" desc:"The vaulted accounts involved" flag:"vaulted-accounts"`
}

// IdsecPCloudBulkAccountActivitiesResult represents the activities result of a single account in a bulk operation.
type IdsecPCloudBulkAccountActivitiesResult struct {
	AccountID  string                        `json:"account_id" mapstructure:"account_id" desc:"The ID of the account" flag:"account-id"`
	Activities []*IdsecPCloudAccountActivity `json:"activities" mapstructure:"activities" desc:"The activities of the account, if the retrieval succeeded" flag:"activities"`
	Error      string                        `json:"error,omitempty" mapstructure:"error,omitempty" desc:"The error that occurred while retrieving the account's activities, if any" flag:"error"`
}
