package models

// IdsecSIACertificatesFilter represents the filtering options for listing SIA certificates.
type IdsecSIACertificatesFilter struct {
	DomainName string `json:"domain_name,omitempty" mapstructure:"domain_name" flag:"domain-name" desc:"Indicates whether to filter by domain name."`
	CertName   string `json:"cert_name,omitempty" mapstructure:"cert_name" flag:"cert-name" desc:"Indicates whether to filter by certificate name."`
}
