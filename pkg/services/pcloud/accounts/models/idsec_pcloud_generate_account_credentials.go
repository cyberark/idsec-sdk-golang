package models

// IdsecPCloudGenerateAccountCredentials represents the details required to generate account credentials.
type IdsecPCloudGenerateAccountCredentials struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which the secret will be generated" flag:"account-id" validate:"required"`
}
