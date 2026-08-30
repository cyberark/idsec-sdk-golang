package models

// IdsecCmgrUninstall represents the details required to uninstall a management agent connector.
type IdsecCmgrUninstall struct {
	ConnectorID        string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID to be uninstalled." validate:"required"`
	ConnectorOS        string `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The operating system type of the target machine (linux, windows)." required:"true" choices:"linux,windows"`
	InstallationPath   string `json:"installation_path,omitempty" mapstructure:"installation_path,omitempty" flag:"installation-path" desc:"The installation path of the connector on the target machine."`
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" required:"true" desc:"The target machine on which to uninstall the connector."`
	Username           string `json:"username" mapstructure:"username" flag:"username" required:"true" desc:"The username used to connect to the target machine."`
	Password           string `json:"password,omitempty" mapstructure:"password,omitempty" flag:"password" desc:"The password used to connect to the target machine."`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path,omitempty" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents,omitempty" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH."`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry the deletion API, if it fails." default:"30"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol to use for WinRM connections (http, https)." default:"https" choices:"http,https"`
	CertificatePath    string `json:"certificate_path,omitempty" mapstructure:"certificate_path,omitempty" flag:"certificate-path" desc:"Path to a custom CA certificate for WinRM HTTPS connections. Only applicable for Windows with HTTPS protocol."`
	TrustCertificate   bool   `json:"trust_certificate,omitempty" mapstructure:"trust_certificate,omitempty" flag:"trust-certificate" desc:"When true, trusts any server certificate for WinRM HTTPS connections. Only applicable for Windows with HTTPS protocol." default:"false"`
	ForceDelete        bool   `json:"force_delete" mapstructure:"force_delete" flag:"force-delete" desc:"When true, forces deletion of the connector even if machine cleanup fails." default:"false"`
}
