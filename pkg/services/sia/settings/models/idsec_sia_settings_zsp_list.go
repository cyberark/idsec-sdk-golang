package models

// IdsecSIASettingsZspList represents the ZSP List feature configuration.
//
// This setting controls whether the ZSP List view is enabled. When disabled,
// the ZSP List view is hidden for all users.
type IdsecSIASettingsZspList struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether the ZSP List feature is enabled"`
}
