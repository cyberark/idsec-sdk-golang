// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAHTTPSRelaySetupScriptRequest represents the request to generate an installation setup script for an HTTPS relay.
type IdsecSIAHTTPSRelaySetupScriptRequest struct {
	HTTPSRelayOS            string         `json:"https_relay_os" mapstructure:"https_relay_os" flag:"https-relay-os" desc:"The OS type of the HTTPS relay host (linux or windows)." validate:"required"`
	ExpirationMinutes       int            `json:"expiration_minutes,omitempty" mapstructure:"expiration_minutes,omitempty" flag:"expiration-minutes" desc:"The number of minutes the setup script will be valid for (15-240). Defaults to 15."`
	ProtocolPortMap         map[string]int `json:"protocol_port_map" mapstructure:"protocol_port_map" flag:"protocol-port-map" desc:"Map between protocol and port." validate:"required"`
	ProxyHost               string         `json:"proxy_host,omitempty" mapstructure:"proxy_host,omitempty" flag:"proxy-host" desc:"The proxy host address for the HTTPS relay."`
	ProxyPort               int            `json:"proxy_port,omitempty" mapstructure:"proxy_port,omitempty" flag:"proxy-port" desc:"The proxy port for the HTTPS relay." default:"443"`
	WindowsInstallationPath string         `json:"windows_installation_path,omitempty" mapstructure:"windows_installation_path,omitempty" flag:"windows-installation-path" desc:"The installation path for the HTTPS relay on Windows machines."`
}
