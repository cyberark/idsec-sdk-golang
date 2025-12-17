package models

// IdsecSIASettingsSshRecording represents the SSH recording configuration for SIA settings.
//
// This model contains configuration options for SSH recording capabilities
// in the Idsec SIA service. It defines whether session recording functionality
// is enabled or disabled for SSH connections, providing control over audit
// and compliance requirements for recording SSH sessions.
type IdsecSIASettingsSshRecording struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether SIA SSH recording is enabled"`
}
