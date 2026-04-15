// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAInstallRelay represents the request to install an HTTPS relay on a target machine.
type IdsecSIAInstallRelay struct {
	HTTPSRelayOS            string         `json:"https_relay_os" mapstructure:"https_relay_os" flag:"https-relay-os" desc:"The OS type of the HTTPS relay host (linux or windows)." validate:"required" choices:"linux,windows"`
	ProtocolPortMap         map[string]int `json:"protocol_port_map" mapstructure:"protocol_port_map" flag:"protocol-port-map" desc:"Map between protocol and port." validate:"required"`
	ExpirationMinutes       int            `json:"expiration_minutes,omitempty" mapstructure:"expiration_minutes,omitempty" flag:"expiration-minutes" desc:"The number of minutes the setup script will be valid for (15-240). Defaults to 15."`
	ProxyHost               string         `json:"proxy_host,omitempty" mapstructure:"proxy_host,omitempty" flag:"proxy-host" desc:"The proxy host address for the HTTPS relay."`
	ProxyPort               int            `json:"proxy_port,omitempty" mapstructure:"proxy_port,omitempty" flag:"proxy-port" desc:"The proxy port for the HTTPS relay." default:"443"`
	WindowsInstallationPath string         `json:"windows_installation_path,omitempty" mapstructure:"windows_installation_path,omitempty" flag:"windows-installation-path" desc:"The installation path for the HTTPS relay on Windows machines."`
	TargetMachine           string         `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to install the HTTPS relay."`
	Username                string         `json:"username" mapstructure:"username" flag:"username" desc:"The username used to connect to the target machine."`
	Password                string         `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password used to connect to the target machine."`
	PrivateKeyPath          string         `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents      string         `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH."`
	RetryCount              int            `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry checking if the relay is active after installation." default:"10"`
	RetryDelay              int            `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol           string         `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol to use for WinRM connections (http or https)." default:"https" choices:"http,https"`
}
