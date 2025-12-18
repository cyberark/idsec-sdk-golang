package models

// IdsecSIAUninstallConnector represents the details required to install a connector.
type IdsecSIAUninstallConnector struct {
	ConnectorOS        string `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system for the connector to uninstall (Linux, Windows)." default:"linux" choices:"linux,windows"`
	ConnectorID        string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID to be uninstalled." validate:"required"`
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to uninstall the connector."`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"The username used to connect to the target machine."`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password used to connect to the target machine."`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH."`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry the deletion API, if it fails." default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol used for WinRM connections (HTTP, HTTPS)." default:"https" choices:"http,https"`
}
