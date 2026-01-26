package models

// IdsecPCloudUpdateAccountCredentialsInVault represents the details required to update account credentials in the vault.
type IdsecPCloudUpdateAccountCredentialsInVault struct {
	AccountID      string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for secrets rotation" flag:"account-id" validate:"required"`
	NewCredentials string `json:"new_credentials" mapstructure:"new_credentials" desc:"The new secret that will be defined for the account. Note: Do not place digits as first or last character. Leading or trailing white spaces will be removed" flag:"new-credentials" validate:"required"`
}
