package models

// IdsecPCloudGetAccount represents the details required to retrieve an account.
type IdsecPCloudGetAccount struct {
	AccountID   string `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account to retrieve the account's details" flag:"account-id"`
	AccountName string `json:"account_name" mapstructure:"account_name" desc:"The name of the account to retrieve the account's details" flag:"account-name"`
}
