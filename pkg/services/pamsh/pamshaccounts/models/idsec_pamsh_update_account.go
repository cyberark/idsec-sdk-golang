package models

// IdsecPamshUpdateAccount represents the details required to update an account.
type IdsecPamshUpdateAccount struct {
	SecretManagement          *IdsecPamshAccountSecretManagement `json:"secret_management,omitempty" mapstructure:"secret_management,omitempty" desc:"Secret management configuration for the account"`
	Secret                    string                             `json:"secret" mapstructure:"secret" desc:"The secret of the account to update" flag:"secret"`
	AccountID                 string                             `json:"id" mapstructure:"id" desc:"The unique ID of the account to updatee" flag:"account-id" validate:"required"`
	Name                      string                             `json:"name,omitempty" mapstructure:"name,omitempty" desc:"Name of the account to update" flag:"name"`
	Address                   string                             `json:"address,omitempty" mapstructure:"address,omitempty" desc:"The name or address of the machine where the account is used" flag:"address"`
	Username                  string                             `json:"username,omitempty" mapstructure:"username,omitempty" desc:"Username of the account to update" flag:"username"`
	PlatformID                string                             `json:"platform_id,omitempty" mapstructure:"platform_id,omitempty" desc:"The platform assigned to this account" flag:"platform-id"`
	PlatformAccountProperties map[string]interface{}             `json:"platform_account_properties,omitempty" mapstructure:"platform_account_properties,omitempty" desc:"The object containing key-value pairs to associate with the account, as defined by the account platform. Optional properties that do not exist or internal properties are not returned" flag:"platform-account-properties"`
}
