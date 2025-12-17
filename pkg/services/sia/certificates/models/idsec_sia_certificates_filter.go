package models

// IdsecSIACertificatesFilter represents the filtering options for listing SIA certificates.
type IdsecSIACertificatesFilter struct {
	DomainName string `json:"domain_name,omitempty" mapstructure:"domain_name" flag:"domain-name" desc:"Filter by domain name"`
	CertName   string `json:"cert_name,omitempty" mapstructure:"cert_name" flag:"cert-name" desc:"Filter by certificate name"`
}
