package models

// IdsecSIASettingsCertificateValidation represents the certificate validation configuration for SIA settings.
//
// This model contains configuration options for certificate validation behavior
// in the Idsec SIA service, including whether validation is enabled or disabled.
type IdsecSIASettingsCertificateValidation struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether certificate validation is enabled"`
}
