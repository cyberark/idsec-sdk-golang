package models

// IdsecSIADBGetSecret is the struct for retrieving a secret from the Idsec SIA DB.
// Deprecated: Use the db-strong-accounts resource instead.
type IdsecSIADBGetSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"The ID of the Secret to get."`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"The name of the Secret to get."`
}
