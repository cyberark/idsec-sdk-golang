package models

// IdsecSIAInstallConnector represents the details required to install a connector.
type IdsecSIAInstallConnector struct {
	ConnectorType      string `json:"connector_type" mapstructure:"connector_type" flag:"connector-type" desc:"The type of the platform on which to install the connector (ON-PREMISE, AWS, AZURE, GCP)." default:"ON-PREMISE" choices:"ON-PREMISE,AWS,AZURE,GCP"`
	ConnectorOS        string `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The type of the operating system on which to install the connector (Linux, windows)." default:"linux" choices:"linux,windows"`
	ConnectorPoolID    string `json:"connector_pool_id" mapstructure:"connector_pool_id" flag:"connector-pool-id" desc:"The connector pool that the connector will be part of. If not provided, the connector is assigned to the default pool." validate:"required"`
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" desc:"The target machine on which to install the connector."`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"The username used to connect to the target machine."`
	Password           string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password used to connect to the target machine."`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH."`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry to connect to the connector, if it fails." default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol to use for WinRM connections (HTTP, HTTPS)." default:"https" choices:"http,https"`
}
