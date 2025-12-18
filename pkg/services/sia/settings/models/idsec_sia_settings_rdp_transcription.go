package models

// IdsecSIASettingsRdpTranscription represents the RDP transcription configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) transcription
// capabilities in the Idsec SIA service. It defines whether session transcription functionality
// is enabled or disabled for RDP connections, providing control over audit and compliance
// requirements for transcribing remote desktop sessions.
type IdsecSIASettingsRdpTranscription struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Indicates whether SIA RDP transcription is enabled."`
}
