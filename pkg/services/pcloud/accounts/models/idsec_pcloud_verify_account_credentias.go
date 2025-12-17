package models

// IdsecPCloudVerifyAccountCredentials represents the details required to verify account credentials.
type IdsecPCloudVerifyAccountCredentials struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The id of the account to mark for validation" flag:"account-id" validate:"required"`
}
