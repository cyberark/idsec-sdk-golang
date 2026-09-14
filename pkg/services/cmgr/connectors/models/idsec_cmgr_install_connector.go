package models

// IdsecCmgrInstall represents the top-level input for installing a management agent connector.
type IdsecCmgrInstall struct {
	// Setup-script fields forwarded to IdsecCmgrGetSetupScript
	ConnectorOS      string                 `json:"connector_os" mapstructure:"connector_os" flag:"connector-os" desc:"The operating system type of the target machine (linux, windows)." required:"true" choices:"linux,windows"`
	ConnectorPoolID  string                 `json:"connector_pool_id" mapstructure:"connector_pool_id,omitempty" flag:"connector-pool-id" required:"true" desc:"The connector pool that the connector will be part of. If not provided, the connector is assigned to the default pool."`
	InstallationPath string                 `json:"installation_path,omitempty" mapstructure:"installation_path,omitempty" flag:"installation-path" desc:"The installation path for the connector on the target machine. Note: cannot be customized on Linux OS and error will be thrown."`
	Version          string                 `json:"version,omitempty" mapstructure:"version,omitempty" flag:"version" desc:"The connector version to install. If not provided, the default stable version according to the tenant configuration will be used."`
	ProxyDetails     *IdsecCmgrProxyDetails `json:"proxy_details,omitempty" mapstructure:"proxy_details,omitempty" flag:"proxy-details" desc:"Optional proxy configuration."`
	TenantInfo       map[string]string      `json:"tenant_info,omitempty" mapstructure:"tenant_info,omitempty" flag:"tenant-info" desc:"Optional tenant metadata (maximum 2 entries)."`

	// Remote-execution fields
	TargetMachine      string `json:"target_machine" mapstructure:"target_machine" flag:"target-machine" required:"true" desc:"The target machine on which to install the connector."`
	Username           string `json:"username" mapstructure:"username" flag:"username" required:"true" desc:"The username used to connect to the target machine."`
	Password           string `json:"password,omitempty" mapstructure:"password,omitempty" flag:"password" desc:"The password used to connect to the target machine." secret:"true"`
	PrivateKeyPath     string `json:"private_key_path,omitempty" mapstructure:"private_key_path,omitempty" flag:"private-key-path" desc:"The private key file path used to connect to the target machine via SSH."`
	PrivateKeyContents string `json:"private_key_contents,omitempty" mapstructure:"private_key_contents,omitempty" flag:"private-key-contents" desc:"The private key contents used to connect to the target machine via SSH." secret:"true"`
	RetryCount         int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry connecting to the target machine." default:"10"`
	RetryDelay         int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
	WinRMProtocol      string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" desc:"The protocol to use for WinRM connections (http, https)." default:"https" choices:"http,https"`
	CertificatePath    string `json:"certificate_path,omitempty" mapstructure:"certificate_path,omitempty" flag:"certificate-path" desc:"Path to a custom CA certificate for WinRM HTTPS connections. Only applicable for Windows with HTTPS protocol."`
	TrustCertificate   bool   `json:"trust_certificate,omitempty" mapstructure:"trust_certificate,omitempty" flag:"trust-certificate" desc:"When true, trusts any server certificate for WinRM HTTPS connections. Only applicable for Windows with HTTPS protocol." default:"false"`
}
