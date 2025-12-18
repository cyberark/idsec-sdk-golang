package models

// IdsecSIADBDeleteSecret is the struct for deleting a secret from the Idsec SIA DB.
type IdsecSIADBDeleteSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"The ID of the Secret to delete."`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"The name of the Secret to delete."`
}

// IdsecSIADBDeleteStrongAccount is the struct for deleting a strong account from the Idsec SIA DB.
type IdsecSIADBDeleteStrongAccount struct {
	ID string `json:"id" mapstructure:"id" flag:"id" validate:"required" desc:"The ID of the account to delete."`
}
