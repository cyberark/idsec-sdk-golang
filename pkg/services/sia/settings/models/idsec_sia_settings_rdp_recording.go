package models

// IdsecSIASettingsRdpRecording represents the RDP recording configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) recording
// capabilities in the Idsec SIA service. It defines whether session recording functionality
// is enabled or disabled for RDP connections, providing control over audit and compliance
// requirements for recording remote desktop sessions.
type IdsecSIASettingsRdpRecording struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether SIA RDP recording is enabled"`
}
