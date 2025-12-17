package models

// IdsecSIAVMAddSecret represents the request to add a secret in a VM.
type IdsecSIAVMAddSecret struct {
	SecretName          string `json:"secret_name" mapstructure:"secret_name" flag:"secret-name" desc:"Name of the secret. For PCloudAccount type, this is auto-generated from account name and safe." validate:"omitempty,min=1"`
	SecretDetails       string `json:"secret_details,omitempty" mapstructure:"secret_details,omitempty" flag:"secret-details" desc:"Optional extra metadata as JSON (use single quotes around JSON). Both secret types include 'certFileName', 'account_domain' (defaults to 'local'), 'ephemeral_domain_user_data'. Example: --secret-details '{\"account_domain\":\"domain\"}'. Additional fields are merged with defaults."`
	SecretType          string `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"Type of the secret to add, data is picked according to the chosen type (ProvisionerUser,PCloudAccount)" validate:"required" choices:"ProvisionerUser,PCloudAccount"`
	IsDisabled          bool   `json:"is_disabled" mapstructure:"is_disabled" flag:"is-disabled" desc:"Whether the secret should be disabled or not" default:"false"`
	ProvisionerUsername string `json:"provisioner_username,omitempty" mapstructure:"provisioner_username,omitempty" flag:"provisioner-username" desc:"If provisioner user type is picked, the username"`
	ProvisionerPassword string `json:"provisioner_password,omitempty" mapstructure:"provisioner_password,omitempty" flag:"provisioner-password" desc:"If provisioner user type is picked, the password"`
	PCloudAccountSafe   string `json:"pcloud_account_safe,omitempty" mapstructure:"pcloud_account_safe,omitempty" flag:"pcloud-account-safe" desc:"If pcloud account type is picked, the account safe"`
	PCloudAccountName   string `json:"pcloud_account_name,omitempty" mapstructure:"pcloud_account_name,omitempty" flag:"pcloud-account-name" desc:"If pcloud account type is picked, the account name"`
}
