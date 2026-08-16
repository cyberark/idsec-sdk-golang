package models

// IdsecPCloudListAccountActivities represents the details required to list an account's activities.
type IdsecPCloudListAccountActivities struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the activities" flag:"account-id" validate:"required"`
	SafeName  string `json:"safe_name,omitempty" mapstructure:"safe_name,omitempty" desc:"The name of the safe to retrieve the activities from, will be resolved automatically if omitted" flag:"safe-name"`
}

// IdsecPCloudBulkListAccountActivities represents the details required to list activities for multiple accounts in parallel.
type IdsecPCloudBulkListAccountActivities struct {
	AccountIDs     []string `json:"account_ids" mapstructure:"account_ids" desc:"The IDs of the accounts to retrieve activities for" flag:"account-ids" validate:"required"`
	SafeName       string   `json:"safe_name,omitempty" mapstructure:"safe_name,omitempty" desc:"The name of the safe to retrieve the activities from, will be resolved automatically for each account if omitted" flag:"safe-name"`
	MaxConcurrency int      `json:"max_concurrency,omitempty" mapstructure:"max_concurrency,omitempty" desc:"The maximum number of accounts to process concurrently (defaults to 32)" flag:"max-concurrency"`
}
