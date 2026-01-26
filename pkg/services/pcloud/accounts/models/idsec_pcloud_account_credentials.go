package models

// IdsecPCloudAccountCredentials represents the credentials of an account.
type IdsecPCloudAccountCredentials struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account" flag:"account-id" validate:"required"`
	Password  string `json:"password" mapstructure:"password" desc:"Secret" flag:"password" validate:"required"`
}
