package models

// IdsecPCloudAccountOverviewCompliance represents the compliance summary of an account overview.
type IdsecPCloudAccountOverviewCompliance struct {
	IsCompliant      bool   `json:"is_compliant" mapstructure:"is_compliant" desc:"Whether the account is compliant" flag:"is-compliant"`
	LastModifiedDate int    `json:"last_modified_date" mapstructure:"last_modified_date" desc:"The date and time the account was last modified (UTC)" flag:"last-modified-date"`
	LastModifiedBy   string `json:"last_modified_by" mapstructure:"last_modified_by" desc:"The user who last modified the account" flag:"last-modified-by"`
	ModificationType string `json:"modification_type" mapstructure:"modification_type" desc:"The type of the last modification" flag:"modification-type"`
}

// IdsecPCloudAccountOverviewDetails represents the detailed properties of an account overview.
type IdsecPCloudAccountOverviewDetails struct {
	LastVerifiedDate   int         `json:"last_verified_date" mapstructure:"last_verified_date" desc:"The date and time the account was last verified (UTC)" flag:"last-verified-date"`
	LastVerifiedBy     string      `json:"last_verified_by" mapstructure:"last_verified_by" desc:"The user who last verified the account" flag:"last-verified-by"`
	LastUsedBy         string      `json:"last_used_by" mapstructure:"last_used_by" desc:"The user who last used the account" flag:"last-used-by"`
	LastUsedDate       int         `json:"last_used_date" mapstructure:"last_used_date" desc:"The date and time the account was last used (UTC)" flag:"last-used-date"`
	CreationDate       int         `json:"creation_date" mapstructure:"creation_date" desc:"The date and time the account was created (UTC)" flag:"creation-date"`
	Name               string      `json:"name" mapstructure:"name" desc:"The name of the account" flag:"name"`
	CreatedTime        int         `json:"created_time" mapstructure:"created_time" desc:"The date and time the account was created (UTC)" flag:"created-time"`
	AccountURL         string      `json:"account_url" mapstructure:"account_url" desc:"The URL of the account" flag:"account-url"`
	ManagedByCPM       bool        `json:"managed_by_cpm" mapstructure:"managed_by_cpm" desc:"Whether the account is managed by the CPM" flag:"managed-by-cpm"`
	CPMDisabled        string      `json:"cpm_disabled" mapstructure:"cpm_disabled" desc:"Whether the CPM is disabled for the account" flag:"cpm-disabled"`
	CPMStatus          string      `json:"cpm_status" mapstructure:"cpm_status" desc:"The CPM status of the account" flag:"cpm-status"`
	CPMErrorDetails    string      `json:"cpm_error_details" mapstructure:"cpm_error_details" desc:"The CPM error details of the account" flag:"cpm-error-details"`
	ImmediateCPMTask   interface{} `json:"immediate_cpm_task" mapstructure:"immediate_cpm_task" desc:"The immediate CPM task for the account" flag:"immediate-cpm-task"`
	DeletedBy          string      `json:"deleted_by" mapstructure:"deleted_by" desc:"The user who deleted the account" flag:"deleted-by"`
	DeletionDate       int         `json:"deletion_date" mapstructure:"deletion_date" desc:"The date and time the account was deleted (UTC)" flag:"deletion-date"`
	LockedBy           string      `json:"locked_by" mapstructure:"locked_by" desc:"The user who locked the account" flag:"locked-by"`
	IsFavorite         bool        `json:"is_favorite" mapstructure:"is_favorite" desc:"Whether the account is marked as a favorite" flag:"is-favorite"`
	IsNew              bool        `json:"is_new" mapstructure:"is_new" desc:"Whether the account is new" flag:"is-new"`
	SafeName           string      `json:"safe_name" mapstructure:"safe_name" desc:"The name of the Safe where the account is stored" flag:"safe-name"`
	IsGroupMember      bool        `json:"is_group_member" mapstructure:"is_group_member" desc:"Whether the account is a member of a group" flag:"is-group-member"`
	DualControlStatus  string      `json:"dual_control_status" mapstructure:"dual_control_status" desc:"The dual control status of the account" flag:"dual-control-status"`
	RequiredProperties interface{} `json:"required_properties" mapstructure:"required_properties" desc:"The required properties of the account" flag:"required-properties"`
	OptionalProperties interface{} `json:"optional_properties" mapstructure:"optional_properties" desc:"The optional properties of the account" flag:"optional-properties"`
	LimitDomainAccess  interface{} `json:"limit_domain_access" mapstructure:"limit_domain_access" desc:"The domain access limitation of the account" flag:"limit-domain-access"`
	AccessDomainList   interface{} `json:"access_domain_list" mapstructure:"access_domain_list" desc:"The list of domains the account can access" flag:"access-domain-list"`
	RequestID          int         `json:"request_id" mapstructure:"request_id" desc:"The ID of the request associated with the account" flag:"request-id"`
	FutureTimeFrame    bool        `json:"future_time_frame" mapstructure:"future_time_frame" desc:"Whether the account access is within a future time frame" flag:"future-time-frame"`
	LinkedAccounts     interface{} `json:"linked_accounts" mapstructure:"linked_accounts" desc:"The accounts linked to this account" flag:"linked-accounts"`
}

// IdsecPCloudAccountOverview represents the overview of an account.
type IdsecPCloudAccountOverview struct {
	Compliance         *IdsecPCloudAccountOverviewCompliance `json:"compliance" mapstructure:"compliance" desc:"The compliance summary of the account" flag:"compliance"`
	Activities         []*IdsecPCloudAccountActivity         `json:"activities" mapstructure:"activities" desc:"The activities performed on the account" flag:"activities"`
	TotalDependencies  interface{}                           `json:"total_dependencies" mapstructure:"total_dependencies" desc:"The total number of dependencies of the account" flag:"total-dependencies"`
	FailedDependencies interface{}                           `json:"failed_dependencies" mapstructure:"failed_dependencies" desc:"The failed dependencies of the account" flag:"failed-dependencies"`
	Recordings         interface{}                           `json:"recordings" mapstructure:"recordings" desc:"The recordings associated with the account" flag:"recordings"`
	Details            *IdsecPCloudAccountOverviewDetails    `json:"details" mapstructure:"details" desc:"The detailed properties of the account" flag:"details"`
	Platform           interface{}                           `json:"platform" mapstructure:"platform" desc:"The platform details of the account" flag:"platform"`
	AvailableTabs      []string                              `json:"available_tabs" mapstructure:"available_tabs" desc:"The tabs available for the account" flag:"available-tabs"`
	ActionsToDisplay   interface{}                           `json:"actions_to_display" mapstructure:"actions_to_display" desc:"The actions to display for the account" flag:"actions-to-display"`
	EnabledActions     interface{}                           `json:"enabled_actions" mapstructure:"enabled_actions" desc:"The actions enabled for the account" flag:"enabled-actions"`
}

// IdsecPCloudBulkAccountOverviewResult represents the overview result of a single account in a bulk operation.
type IdsecPCloudBulkAccountOverviewResult struct {
	AccountID string                      `json:"account_id" mapstructure:"account_id" desc:"The ID of the account" flag:"account-id"`
	Overview  *IdsecPCloudAccountOverview `json:"overview" mapstructure:"overview" desc:"The overview of the account, if the retrieval succeeded" flag:"overview"`
	Error     string                      `json:"error,omitempty" mapstructure:"error,omitempty" desc:"The error that occurred while retrieving the account's overview, if any" flag:"error"`
}
