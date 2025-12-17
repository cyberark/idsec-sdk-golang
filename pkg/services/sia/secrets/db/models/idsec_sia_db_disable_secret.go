package models

// IdsecSIADBDisableSecret is the struct for disabling a secret in the Idsec SIA DB.
type IdsecSIADBDisableSecret struct {
	SecretID   string `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret to disable"`
	SecretName string `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"Name of the secret to disable"`
}
