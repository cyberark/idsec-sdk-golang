// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAUninstallRelay represents the details required to uninstall an HTTPS relay.
type IdsecSIAUninstallRelay struct {
	HTTPSRelayOS       string `json:"https_relay_os" mapstructure:"https_relay_os" flag:"https-relay-os" desc:"The type of the operating system for the HTTPS relay to uninstall (linux, windows)." default:"linux" choices:"linux,windows"`
	ID                 string `json:"https_relay_id" mapstructure:"https_relay_id" flag:"https-relay-id" desc:"The HTTPS relay ID to be uninstalled." validate:"required"`
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to uninstall the HTTPS relay."`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"The username used to connect to the target machine."`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password used to connect to the target machine."`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH."`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry the deletion API, if it fails." default:"30"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol used for WinRM connections (http, https)." default:"https" choices:"http,https"`
	ForceDelete        bool   `json:"force_delete" mapstructure:"force_delete" flag:"force-delete" desc:"When true, forces deletion of the HTTPS relay even if it has active sessions." default:"false"`
}
