package models

// IdsecSIASettingsRdpFileTransfer represents the RDP file transfer configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) file transfer
// capabilities in the Idsec SIA service. It defines whether file transfer functionality
// is enabled or disabled for RDP connections, providing control over data movement
// between local and remote systems during RDP sessions.
type IdsecSIASettingsRdpFileTransfer struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether RDP file transfer is enabled"`
}
