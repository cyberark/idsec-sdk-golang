package models

// IdsecSIAVMChangeSecret represents the request to change a secret in a VM.
type IdsecSIAVMChangeSecret struct {
	SecretID            string `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"The Secret ID to change." validate:"required"`
	SecretName          string `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"The new name of the Secret."`
	SecretDetails       string `json:"secret_details,omitempty" mapstructure:"secret_details,omitempty" flag:"secret-details" desc:"The new Secret details as JSON (use single quotes around JSON). Merges with existing values. Example: --secret-details '{\"account_domain\":\"MYDOMAIN\"}'. If not provided, the existing details are preserved."`
	IsDisabled          bool   `json:"is_disabled,omitempty" mapstructure:"is_disabled,omitempty" flag:"is-disabled" desc:"Indicates whether to disable the Secret." default:"false"`
	ProvisionerUsername string `json:"provisioner_username,omitempty" mapstructure:"provisioner_username,omitempty" flag:"provisioner-username" desc:"If provisioner user type Secret, the new username."`
	ProvisionerPassword string `json:"provisioner_password,omitempty" mapstructure:"provisioner_password,omitempty" flag:"provisioner-password" desc:"If provisioner user type Secret, the new password."`
	PCloudAccountSafe   string `json:"pcloud_account_safe,omitempty" mapstructure:"pcloud_account_safe,omitempty" flag:"pcloud-account-safe" desc:"If Priviledge Cloud account type Secret, the new account Safe."`
	PCloudAccountName   string `json:"pcloud_account_name,omitempty" mapstructure:"pcloud_account_name,omitempty" flag:"pcloud-account-name" desc:"If Priviledge Cloud account type Secret, the new account name."`
}
