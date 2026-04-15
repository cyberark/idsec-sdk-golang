package models

// IdsecSIASettingsRdpFileParameters represents the RDP file parameters configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) file parameters
// in the Idsec SIA service. It defines settings related to credentials delegation
// for RDP connections.
type IdsecSIASettingsRdpFileParameters struct {
	DisableCredentialsDelegation *bool `json:"disable_credentials_delegation,omitempty" mapstructure:"disable_credentials_delegation,omitempty" flag:"disable-credentials-delegation" desc:"Choose to ignore or disable credential delegation parameter."`
}
