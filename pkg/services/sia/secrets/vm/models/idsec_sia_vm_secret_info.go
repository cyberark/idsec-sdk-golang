package models

// IdsecSIAVMSecretInfo represents the information about a secret in a VM.
type IdsecSIAVMSecretInfo struct {
	SecretID      string                 `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"The ID of the Secret."`
	TenantID      string                 `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"The Tenant ID of the Secret."`
	SecretType    string                 `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"The type of the Secret." choices:"ProvisionerUser,PCloudAccount"`
	SecretName    string                 `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"A friendly name label."`
	SecretDetails map[string]interface{} `json:"secret_details" mapstructure:"secret_details" flag:"secret-details" desc:"The extra details of the Secret."`
	IsActive      bool                   `json:"is_active" mapstructure:"is_active" flag:"is-active" desc:"Indicates whether the Secret is active."`
}
