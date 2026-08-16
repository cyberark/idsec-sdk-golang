package models

// IdsecCmgrGetSetupScript represents the request body for POST api/setup-script.
type IdsecCmgrGetSetupScript struct {
	OsType           string                 `json:"os_type" mapstructure:"os_type" flag:"os-type" desc:"The operating system type of the target machine (linux, windows)." required:"true" choices:"linux,windows"`
	ConnectorPoolID  string                 `json:"connector_pool_id" mapstructure:"connector_pool_id,omitempty" flag:"connector-pool-id" required:"true" desc:"The connector pool that the connector will be part of. If not provided, the connector is assigned to the default pool."`
	InstallationPath string                 `json:"installation_path,omitempty" mapstructure:"installation_path,omitempty" flag:"installation-path" desc:"The installation path for the connector on the target machine. Note: cannot be customized on Linux OS and error will be thrown."`
	Version          string                 `json:"version,omitempty" mapstructure:"version,omitempty" flag:"version" desc:"The connector version to install."`
	ProxyDetails     *IdsecCmgrProxyDetails `json:"proxy_details,omitempty" mapstructure:"proxy_details,omitempty" flag:"proxy-details" desc:"Optional proxy configuration."`
	TenantInfo       map[string]string      `json:"tenant_info,omitempty" mapstructure:"tenant_info,omitempty" flag:"tenant-info" desc:"Optional tenant metadata (maximum 2 entries)."`
}
