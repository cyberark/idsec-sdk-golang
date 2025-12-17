package models

// IdsecSIAVMGetSecret represents the request to get a secret in a VM.
type IdsecSIAVMGetSecret struct {
	SecretID string `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"The secret id to get" validate:"required"`
}
