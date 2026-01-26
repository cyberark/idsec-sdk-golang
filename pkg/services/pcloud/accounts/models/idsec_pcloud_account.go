package models

// Possible Secret Types
const (
	Password = "password"
	Key      = "key"
)

// IdsecPCloudAccountSecretManagement represents the secret management properties of an account.
type IdsecPCloudAccountSecretManagement struct {
	AutomaticManagementEnabled bool   `json:"automatic_management_enabled,omitempty" mapstructure:"automatic_management_enabled,omitempty" desc:"Whether the account secret is managed automatically" flag:"automatic-management-enabled"`
	ManualManagementReason     string `json:"manual_management_reason,omitempty" mapstructure:"manual_management_reason,omitempty" desc:"The reason for disabling automatic management" flag:"manual-management-reason"`
	LastModifiedTime           int    `json:"last_modified_time,omitempty" mapstructure:"last_modified_time,omitempty" desc:"Last time the account was modified" flag:"last-modified-time"`
}

// IdsecPCloudAccountRemoteMachinesAccess represents the remote machine access properties of an account.
type IdsecPCloudAccountRemoteMachinesAccess struct {
	RemoteMachines                   []string `json:"remote_machines,omitempty" mapstructure:"remote_machines,omitempty" desc:"List of remote machines that the account can access, separated by semicolons" flag:"remote-machines"`
	AccessRestrictedToRemoteMachines bool     `json:"access_restricted_to_remote_machines,omitempty" mapstructure:"access_restricted_to_remote_machines,omitempty" desc:"Whether to restrict access only to the specified remote machines" flag:"access-restricted-to-remote-machines"`
}

// IdsecPCloudAccount represents the full properties of an account.
type IdsecPCloudAccount struct {
	IdsecPCloudAccountSecretManagement     `mapstructure:",squash"`
	IdsecPCloudAccountRemoteMachinesAccess `mapstructure:",squash"`
	AccountID                              string                 `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account" flag:"account-id" validate:"required"`
	Status                                 string                 `json:"status,omitempty" mapstructure:"status,omitempty" desc:"The account's management status" flag:"status"`
	CreatedTime                            int                    `json:"created_time,omitempty" mapstructure:"created_time,omitempty" desc:"The date and time the account was created" flag:"created-time"`
	CategoryModificationTime               int                    `json:"category_modification_time,omitempty" mapstructure:"category_modification_time,omitempty" desc:"The last time the account or one of its file categories was created or changed" flag:"category-modification-time"`
	Name                                   string                 `json:"name" mapstructure:"name" desc:"The name of the account" flag:"name" validate:"required"`
	SafeName                               string                 `json:"safe_name" mapstructure:"safe_name" desc:"The name of the Safe where the account is stored" flag:"safe-name" validate:"required"`
	PlatformID                             string                 `json:"platform_id,omitempty" mapstructure:"platform_id,omitempty" desc:"The ID of the platform assigned to the account" flag:"platform-id"`
	Username                               string                 `json:"username,omitempty" mapstructure:"username,omitempty" desc:"The account username" flag:"username"`
	Address                                string                 `json:"address,omitempty" mapstructure:"address,omitempty" desc:"The name or address of the machine where the account is used" flag:"address"`
	SecretType                             string                 `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" desc:"The type of secret (password,key)" flag:"secret-type" choices:"password,key"`
	PlatformAccountProperties              map[string]interface{} `json:"platform_account_properties,omitempty" mapstructure:"platform_account_properties,omitempty" desc:"The object containing key-value pairs to associate with the account, as defined by the account platform. Optional properties that do not exist or internal properties are not returned" flag:"platform-account-properties"`
}
