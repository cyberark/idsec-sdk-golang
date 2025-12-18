package models

// IdsecSIASettingsLogonSequence represents the logon sequence configuration for SIA settings.
//
// This model contains configuration options for the tenant logon sequence behavior
// in the Idsec SIA service. It defines the sequence of steps or actions that should
// be performed during the authentication and login process for tenant users.
type IdsecSIASettingsLogonSequence struct {
	AlwaysUseSia  *bool   `json:"always_use_sia,omitempty" mapstructure:"always_use_sia,omitempty" flag:"always-use-sia" desc:"Indicates whether to always use SIA for the logon sequence."`
	LogonSequence *string `json:"logon_sequence,omitempty" mapstructure:"logon_sequence,omitempty" flag:"logon-sequence" desc:"The configuration for the tenant logon sequence."`
}
