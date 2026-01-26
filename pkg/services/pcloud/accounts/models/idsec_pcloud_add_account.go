package models

// IdsecPCloudAddAccount represents the details required to add an account.
type IdsecPCloudAddAccount struct {
	// Using inheritance on those for easier translation for CLI params
	IdsecPCloudAccountSecretManagement     `mapstructure:",squash"`
	IdsecPCloudAccountRemoteMachinesAccess `mapstructure:",squash"`
	Secret                                 string                 `json:"secret" mapstructure:"secret" desc:"The secret value." flag:"secret"`
	Name                                   string                 `json:"name" mapstructure:"name,omitempty" desc:"Name of the account" flag:"name"`
	SafeName                               string                 `json:"safe_name" mapstructure:"safe_name" desc:"The Safe where the account will be created" flag:"safe-name" validate:"required"`
	PlatformID                             string                 `json:"platform_id,omitempty" mapstructure:"platform_id,omitempty" desc:"The platform assigned to this account" flag:"platform-id"`
	Username                               string                 `json:"username,omitempty" mapstructure:"username,omitempty" desc:"Account user's name" flag:"username"`
	Address                                string                 `json:"address,omitempty" mapstructure:"address,omitempty" desc:"The name or address of the machine where the account will be used" flag:"address"`
	SecretType                             string                 `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" desc:"The type of secret for the acccount (password,key)" flag:"secret-type" choices:"password,key"`
	PlatformAccountProperties              map[string]interface{} `json:"platform_account_properties,omitempty" mapstructure:"platform_account_properties,omitempty" desc:"The object containing key-value pairs to associate with the account, as defined by the account platform. Optional properties that do not exist or internal properties are not returned" flag:"platform-account-properties"`
}
