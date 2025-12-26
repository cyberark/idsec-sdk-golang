package models

// IdsecSIADBGetSecret is the struct for retrieving a secret from the Idsec SIA DB.
type IdsecSIADBGetSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"The ID of the Secret to get."`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"The name of the Secret to get."`
}

// IdsecSIADBGetStrongAccount is the struct for retrieving a strong account from the Idsec SIA DB.
type IdsecSIADBGetStrongAccount struct {
	StrongAccountID string `json:"strong_account_id" mapstructure:"strong_account_id" flag:"strong-account-id" validate:"required" desc:"The ID of the account to get."`
}
