package models

// IdsecSIAVMDeleteSecret represents the request to delete a secret in a VM.
type IdsecSIAVMDeleteSecret struct {
	SecretID string `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"The secret id to delete" validate:"required"`
}
