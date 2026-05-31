// Package models provides request and response model types for the SIA settings service.
package models

// IdsecSIASettingsHTTPSRelay represents the HTTPS Relay configuration for SIA settings.
//
// This model contains configuration options for the HTTPS Relay feature in the
// Idsec SIA service, including whether the feature is enabled, the relay host
// address, and the SSH port used by the relay.
type IdsecSIASettingsHTTPSRelay struct {
	IsHTTPSRelayEnabled *bool   `json:"is_https_relay_enabled,omitempty" mapstructure:"is_https_relay_enabled,omitempty" flag:"is-https-relay-enabled" desc:"Indicates whether the HTTPS relay feature is enabled."`
	RelayHost           *string `json:"relay_host,omitempty" mapstructure:"relay_host,omitempty" flag:"relay-host" desc:"The HTTPS relay host address (FQDN or IP)."`
	SSHRelayPort        *int    `json:"ssh_relay_port,omitempty" mapstructure:"ssh_relay_port,omitempty" flag:"ssh-relay-port" desc:"The SSH port used by the HTTPS relay."`
}
