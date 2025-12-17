package models

// IdsecSIACertificatesAddCertificate represents the input parameters for adding a SIA certificate.
type IdsecSIACertificatesAddCertificate struct {
	CertType        string                 `json:"cert_type,omitempty" mapstructure:"cert_type,omitempty" flag:"cert-type" desc:"Certificate type (PEM,DER)" choices:"PEM,DER"`
	CertPassword    string                 `json:"cert_password,omitempty" mapstructure:"cert_password,omitempty" flag:"cert-password" desc:"Encryption password for certificate"`
	CertName        string                 `json:"cert_name,omitempty" mapstructure:"cert_name,omitempty" flag:"cert-name" desc:"Name of the certificate"`
	CertDescription string                 `json:"cert_description,omitempty" mapstructure:"cert_description,omitempty" flag:"cert-description" desc:"Description of the certificate"`
	DomainName      string                 `json:"domain_name,omitempty" mapstructure:"domain_name,omitempty" flag:"domain-name" desc:"Domain to which the certificate is assigned"`
	CertificateBody string                 `json:"certificate_body,omitempty" mapstructure:"certificate_body,omitempty" flag:"certificate-body" desc:"Certificate body content"`
	File            string                 `json:"file,omitempty" mapstructure:"file,omitempty" flag:"file" desc:"Path to a file with the certificate body"`
	Labels          map[string]interface{} `json:"labels,omitempty" mapstructure:"labels,omitempty" flag:"labels" desc:"Additional labels assigned to the certificate"`
}
