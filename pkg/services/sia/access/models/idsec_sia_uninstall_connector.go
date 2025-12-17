package models

// IdsecSIAUninstallConnector represents the details required to install a connector.
type IdsecSIAUninstallConnector struct {
	ConnectorOS        string `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system for the connector to uninstall (linux,windows)" default:"linux" choices:"linux,windows"`
	ConnectorID        string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID to be uninstalled" validate:"required"`
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"Target machine on which to uninstall the connector on"`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"Username to connect with to the target machine"`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"Password to connect with to the target machine"`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"Private key file path to use for connecting to the target machine via ssh"`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"Private key contents to use for connecting to the target machine via ssh"`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"Number of times to retry the deletion API if it fails" default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"Delay in seconds between retries" default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol to use for WinRM connection (http,https)" default:"https" choices:"http,https"`
}
