package models

// IdsecPCloudSetAccountNextCredentials represents the details required to set the next credentials for an account.
type IdsecPCloudSetAccountNextCredentials struct {
	AccountID      string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to set the secret" flag:"account-id" validate:"required"`
	NewCredentials string `json:"new_credentials" mapstructure:"new_credentials" desc:"The new secret that will be defined for the account. Note: Do not place digits as first or last character. Leading or trailing white spaces will be removed" flag:"new-credentials" validate:"required"`
}
