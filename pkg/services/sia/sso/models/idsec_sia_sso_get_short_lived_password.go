package models

// IdsecSIASSOGetShortLivedPassword is a struct that represents the request for getting a short-lived password from the Idsec SIA SSO service.
type IdsecSIASSOGetShortLivedPassword struct {
	AllowCaching bool   `json:"allow_caching" mapstructure:"allow_caching" flag:"allow-caching" desc:"Indicates whether to allow short-lived token caching." default:"false"`
	Service      string `json:"service" mapstructure:"service" flag:"service" desc:"The service for which to get the token info." choices:"DPA-DB,DPA-RDP" default:"DPA-DB"`
}
