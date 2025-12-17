package models

// IdsecSIADBGetSecret is the struct for retrieving a secret from the Idsec SIA DB.
type IdsecSIADBGetSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret to get"`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"Name of the secret to get"`
}

// IdsecSIADBGetStrongAccount is the struct for retrieving a strong account from the Idsec SIA DB.
type IdsecSIADBGetStrongAccount struct {
	ID string `json:"id" mapstructure:"id" flag:"id" validate:"required" desc:"ID of the account to get"`
}
