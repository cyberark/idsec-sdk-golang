package models

// IdsecPCloudGetAccountOverview represents the details required to retrieve an account's overview.
type IdsecPCloudGetAccountOverview struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the overview" flag:"account-id" validate:"required"`
}

// IdsecPCloudBulkGetAccountOverview represents the details required to retrieve the overview for multiple accounts in parallel.
type IdsecPCloudBulkGetAccountOverview struct {
	AccountIDs     []string `json:"account_ids" mapstructure:"account_ids" desc:"The IDs of the accounts to retrieve the overview for" flag:"account-ids" validate:"required"`
	MaxConcurrency int      `json:"max_concurrency,omitempty" mapstructure:"max_concurrency,omitempty" desc:"The maximum number of accounts to process concurrently (defaults to 32)" flag:"max-concurrency"`
}
