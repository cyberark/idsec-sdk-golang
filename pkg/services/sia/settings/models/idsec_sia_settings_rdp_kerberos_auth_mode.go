package models

// Possible values for IdsecSIASettingsRdpKerberosAuthMode.AuthMode
const (
	IdsecSIASettingsRdpKerberosAuthModeDoNotUse  = "DO_NOT_USE"
	IdsecSIASettingsRdpKerberosAuthModeNegotiate = "NEGOTIATE"
	IdsecSIASettingsRdpKerberosAuthModeEnforce   = "ENFORCE"
)

// IdsecSIASettingsRdpKerberosAuthMode represents the RDP Kerberos authentication mode configuration for SIA settings.
//
// This model contains configuration options for the Kerberos authentication mode
// used in Remote Desktop Protocol (RDP) connections within the Idsec SIA service.
// It defines how Kerberos authentication is handled for RDP sessions, providing
// control over security and access management for remote desktop connections.
type IdsecSIASettingsRdpKerberosAuthMode struct {
	AuthMode *string `json:"auth_mode,omitempty" mapstructure:"auth_mode,omitempty" flag:"auth-mode" desc:"The Kerberos authentication mode for RDP connections (DO_NOT_USE,NEGOTIATE,ENFORCE)" choices:"DO_NOT_USE,NEGOTIATE,ENFORCE"`
}
