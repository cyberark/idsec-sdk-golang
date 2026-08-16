package models

// IdsecPCloudGetAccountComplianceInfo represents the details required to retrieve an account's compliance info.
type IdsecPCloudGetAccountComplianceInfo struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the compliance info" flag:"account-id" validate:"required"`
}

// IdsecPCloudBulkGetAccountComplianceInfo represents the details required to retrieve compliance info for multiple accounts in parallel.
type IdsecPCloudBulkGetAccountComplianceInfo struct {
	AccountIDs     []string `json:"account_ids" mapstructure:"account_ids" desc:"The IDs of the accounts to retrieve compliance info for" flag:"account-ids" validate:"required"`
	MaxConcurrency int      `json:"max_concurrency,omitempty" mapstructure:"max_concurrency,omitempty" desc:"The maximum number of accounts to process concurrently (defaults to 32)" flag:"max-concurrency"`
}
