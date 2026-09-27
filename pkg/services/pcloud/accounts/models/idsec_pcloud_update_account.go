package models

// IdsecPCloudUpdateAccountSecretManagement mirrors IdsecPCloudAccountSecretManagement with every
// optional field nilable. Update needs to distinguish "the caller did not supply this" from "the
// caller supplied the zero value"; the read and create models do not, and are deliberately left
// alone. LastModifiedTime is intentionally absent: the pCloud API rejects attempts to PATCH it
// (it is a server-managed timestamp; see pamshAccountUpdateExcludedPatchPaths for the same
// restriction on the pamsh service).
type IdsecPCloudUpdateAccountSecretManagement struct {
	AutomaticManagementEnabled *bool   `json:"automatic_management_enabled,omitempty" mapstructure:"automatic_management_enabled,omitempty" desc:"Whether the account secret is managed automatically" flag:"automatic-management-enabled"`
	ManualManagementReason     *string `json:"manual_management_reason,omitempty" mapstructure:"manual_management_reason,omitempty" desc:"The reason for disabling automatic management" flag:"manual-management-reason"`
}

// IdsecPCloudUpdateAccountRemoteMachinesAccess mirrors IdsecPCloudAccountRemoteMachinesAccess with
// every field nilable, for the same reason as above.
type IdsecPCloudUpdateAccountRemoteMachinesAccess struct {
	RemoteMachines                   []string `json:"remote_machines,omitempty" mapstructure:"remote_machines,omitempty" desc:"List of remote machines that the account can access, separated by semicolons" flag:"remote-machines"`
	AccessRestrictedToRemoteMachines *bool    `json:"access_restricted_to_remote_machines,omitempty" mapstructure:"access_restricted_to_remote_machines,omitempty" desc:"Whether to restrict access only to the specified remote machines" flag:"access-restricted-to-remote-machines"`
}

// IdsecPCloudUpdateAccount represents the details required to update an account.
//
// Every field except AccountID is nilable: on update, nil means "the caller did not supply this
// field", and the field is left out of the PATCH entirely. This is what lets the Terraform
// provider send only the attributes a practitioner actually changed.
type IdsecPCloudUpdateAccount struct {
	IdsecPCloudUpdateAccountSecretManagement     `mapstructure:",squash"`
	IdsecPCloudUpdateAccountRemoteMachinesAccess `mapstructure:",squash"`
	Secret                                       *string                `json:"secret" mapstructure:"secret" desc:"The secret of the account to update" flag:"secret" secret:"true"`
	SecretFile                                   *string                `json:"secret_file" mapstructure:"secret_file" desc:"The path to the secret file." flag:"secret-file"`
	AccountID                                    string                 `json:"account_id" mapstructure:"account_id" desc:"The unique ID of the account to updatee" flag:"account-id" validate:"required"`
	Name                                         *string                `json:"name,omitempty" mapstructure:"name,omitempty" desc:"Name of the account to update" flag:"name" maxlength:"170"`
	Address                                      *string                `json:"address,omitempty" mapstructure:"address,omitempty" desc:"The name or address of the machine where the account is used" flag:"address"`
	Username                                     *string                `json:"username,omitempty" mapstructure:"username,omitempty" desc:"Username of the account to update" flag:"username"`
	PlatformID                                   *string                `json:"platform_id,omitempty" mapstructure:"platform_id,omitempty" desc:"The platform assigned to this account" flag:"platform-id"`
	PlatformAccountProperties                    map[string]interface{} `json:"platform_account_properties,omitempty" mapstructure:"platform_account_properties,omitempty" desc:"The object containing key-value pairs to associate with the account, as defined by the account platform. Optional properties that do not exist or internal properties are not returned" flag:"platform-account-properties"`
}
