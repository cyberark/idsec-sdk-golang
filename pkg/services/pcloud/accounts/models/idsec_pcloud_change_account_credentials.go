package models

// IdsecPCloudChangeAccountCredentials represents the details required to change account credentials.
type IdsecPCloudChangeAccountCredentials struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account to update" flag:"account-id" validate:"required"`
}
