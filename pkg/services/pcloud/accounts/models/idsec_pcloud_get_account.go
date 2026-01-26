package models

// IdsecPCloudGetAccount represents the details required to retrieve an account.
type IdsecPCloudGetAccount struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account to retrieve the account's details" flag:"account-id" validate:"required"`
}
