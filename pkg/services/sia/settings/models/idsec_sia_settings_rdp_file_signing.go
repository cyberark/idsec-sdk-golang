package models

// IdsecSIASettingsRdpFileSigning represents the RDP file signing configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) file signing
// in the Idsec SIA service. It defines settings for enabling/disabling the feature
// and specifying the PFX certificate secret used for signing RDP files.
type IdsecSIASettingsRdpFileSigning struct {
	Enabled     *bool   `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Choose to enable or disable RDP file signing feature."`
	PfxSecretId *string `json:"pfx_secret_id,omitempty" mapstructure:"pfx_secret_id,omitempty" flag:"pfx-secret-id" desc:"Secret ID of the uploaded PFX certificate stored in ADB secrets service."`
}
