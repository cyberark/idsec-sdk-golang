package models

// IdsecSIADBEnableSecret is the struct for enabling a secret in the Idsec SIA DB.
type IdsecSIADBEnableSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"The ID of the Secret to enable."`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"The name of the Secret to enable."`
}
