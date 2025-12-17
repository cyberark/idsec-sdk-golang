package models

// IdsecPCloudGenerateAccountCredentials represents the details required to generate account credentials.
type IdsecPCloudGenerateAccountCredentials struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The id of the account to generate the password for" flag:"account-id" validate:"required"`
}
