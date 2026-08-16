package models

// IdsecCmgrProxyDetails represents proxy configuration for a connector installation.
type IdsecCmgrProxyDetails struct {
	ProxyAddress string `json:"proxy_address" mapstructure:"proxy_address" flag:"proxy-address" required:"true" desc:"The proxy address."`
	ProxyPort    int    `json:"proxy_port" mapstructure:"proxy_port" flag:"proxy-port" required:"true" desc:"The proxy port."`
}
