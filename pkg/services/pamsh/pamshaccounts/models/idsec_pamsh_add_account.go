package models

import "encoding/json"

// IdsecPamshAddAccountSecretManagement represents secret management settings for PVWA Add Account v10.
type IdsecPamshAddAccountSecretManagement struct {
	AutomaticManagementEnabled bool   `json:"automatic_management_enabled" mapstructure:"automatic_management_enabled" desc:"Whether the account secret is managed automatically" flag:"automatic-management-enabled"`
	ManualManagementReason     string `json:"manual_management_reason,omitempty" mapstructure:"manual_management_reason,omitempty" desc:"The reason for disabling automatic management" flag:"manual-management-reason"`
	LastModifiedTime           int    `json:"last_modified_time,omitempty" mapstructure:"last_modified_time,omitempty" desc:"Last time the account was modified" flag:"last-modified-time"`
}

// MarshalJSON serializes secret management for PVWA Add Account v10.
// The block is omitted unless automatic management is enabled.
func (s IdsecPamshAddAccountSecretManagement) MarshalJSON() ([]byte, error) {
	if !s.AutomaticManagementEnabled {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		AutomaticManagementEnabled bool   `json:"automatic_management_enabled"`
		ManualManagementReason     string `json:"manual_management_reason,omitempty"`
		LastModifiedTime           int    `json:"last_modified_time,omitempty"`
	}{
		AutomaticManagementEnabled: s.AutomaticManagementEnabled,
		ManualManagementReason:     s.ManualManagementReason,
		LastModifiedTime:           s.LastModifiedTime,
	})
}

// IdsecPamshAddAccount represents the details required to add an account.
type IdsecPamshAddAccount struct {
	SecretManagement          *IdsecPamshAccountSecretManagement `json:"secret_management,omitempty" mapstructure:"secret_management,omitempty" desc:"Secret management configuration for the account"`
	Secret                    string                             `json:"secret" mapstructure:"secret" desc:"The secret value." flag:"secret"`
	Name                      string                             `json:"name" mapstructure:"name,omitempty" desc:"Name of the account" flag:"name"`
	SafeName                  string                             `json:"safe_name" mapstructure:"safe_name" desc:"The Safe where the account will be created" flag:"safe-name" validate:"required"`
	PlatformID                string                             `json:"platform_id,omitempty" mapstructure:"platform_id,omitempty" desc:"The platform assigned to this account" flag:"platform-id"`
	Username                  string                             `json:"username,omitempty" mapstructure:"username,omitempty" desc:"Account user's name" flag:"username"`
	Address                   string                             `json:"address,omitempty" mapstructure:"address,omitempty" desc:"The name or address of the machine where the account will be used" flag:"address"`
	SecretType                string                             `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" desc:"The type of secret for the acccount (password,key)" flag:"secret-type" choices:"password,key"`
	PlatformAccountProperties map[string]interface{}             `json:"platform_account_properties,omitempty" mapstructure:"platform_account_properties,omitempty" desc:"The object containing key-value pairs to associate with the account, as defined by the account platform. Optional properties that do not exist or internal properties are not returned" flag:"platform-account-properties"`
}
