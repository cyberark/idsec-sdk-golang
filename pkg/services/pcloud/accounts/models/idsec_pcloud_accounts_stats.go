package models

// IdsecPCloudAccountsStats represents the statistics of accounts.
type IdsecPCloudAccountsStats struct {
	AccountsCount             int            `json:"accounts_count" mapstructure:"accounts_count" desc:"Number of accounts" flag:"accounts-count"`
	AccountsCountByPlatformID map[string]int `json:"accounts_count_by_platform_id" mapstructure:"accounts_count_by_platform_id" desc:"Number of accounts per platform ID" flag:"accounts-count-by-platform-id"`
	AccountsCountBySafeName   map[string]int `json:"accounts_count_by_safe_name" mapstructure:"accounts_count_by_safe_name" desc:"Number of accounts per Safe" flag:"accounts-count-by-safe-name"`
}
