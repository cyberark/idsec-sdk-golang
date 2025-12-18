package models

// Certificate types
const (
	IdsecCertificateTypePEM = "PEM"
	IdsecCertificateTypeDER = "DER"
)

// IdsecSIACertificatesCertificateMetadata represents metadata information of a certificate.
type IdsecSIACertificatesCertificateMetadata struct {
	Issuer       string `json:"issuer" mapstructure:"issuer" flag:"issuer" desc:"The issuer of the certificate."`
	Subject      string `json:"subject" mapstructure:"subject" flag:"subject" desc:"The subject of the certificate."`
	ValidFrom    string `json:"valid_from" mapstructure:"valid_from" flag:"valid-from" desc:"The start date of the certificate's validity period."`
	ValidTo      string `json:"valid_to" mapstructure:"valid_to" flag:"valid-to" desc:"The end date of the certificate's validity period."`
	SerialNumber string `json:"serial_number" mapstructure:"serial_number" flag:"serial-number" desc:"The serial number of the certificate."`
}

// IdsecSIACertificatesCertificate represents a SIA certificate with its details.
type IdsecSIACertificatesCertificate struct {
	TenantID        string                                `json:"tenant_id" mapstructure:"tenant_id" flag:"tenant-id" desc:"The ID of the tenant."`
	CertificateID   string                                `json:"certificate_id" mapstructure:"certificate_id" flag:"certificate-id" desc:"The ID of the certificate."`
	DomainName      string                                `json:"domain_name,omitempty" mapstructure:"domain_name" flag:"domain-name" desc:"The domain to which the certificate is assigned."`
	CertBody        string                                `json:"cert_body" mapstructure:"cert_body" flag:"cert-body" desc:"The body content of the certificate."`
	CertName        string                                `json:"cert_name,omitempty" mapstructure:"cert_name" flag:"cert-name" desc:"The name of the certificate."`
	CertDescription string                                `json:"cert_description,omitempty" mapstructure:"cert_description" flag:"cert-description" desc:"The description of the certificate."`
	ExpirationDate  string                                `json:"expiration_date" mapstructure:"expiration_date" flag:"expiration-date" desc:"The time when certificate will expire."`
	CreatedBy       string                                `json:"created_by,omitempty" mapstructure:"created_by" flag:"created-by" desc:"The author of the certificate entry."`
	LastUpdatedBy   string                                `json:"last_updated_by,omitempty" mapstructure:"last_updated_by" flag:"last-updated-by" desc:"The author of last certificate entry update."`
	Checksum        string                                `json:"checksum" mapstructure:"checksum" flag:"checksum" desc:"The checksum calculated from the certificate content."`
	Version         uint                                  `json:"version" mapstructure:"version" flag:"version" desc:"The version of the certificate."`
	Metadata        IdsecSIACertificatesCertificateMetadata `json:"metadata" mapstructure:"metadata" flag:"metadata" desc:"The metadata of the certificate."`
	UpdatedTime     string                                `json:"updated_time" mapstructure:"updated_time" flag:"updated-time" desc:"The datetime of the last certificate update."`
	Labels          map[string]interface{}                `json:"labels,omitempty" mapstructure:"labels" flag:"labels" desc:"The additional labels assigned to the certificate."`
}

// IdsecSIACertificatesShortCertificate represents a shortened version of a SIA certificate.
type IdsecSIACertificatesShortCertificate struct {
	CertificateID   string                                `json:"certificate_id" mapstructure:"certificate_id" flag:"certificate-id" desc:"The ID of the certificate."`
	Body            string                                `json:"body" mapstructure:"body" flag:"body" desc:"The body content of the certificate."`
	Domain          string                                `json:"domain,omitempty" mapstructure:"domain" flag:"domain" desc:"The domain to which the certificate is assigned."`
	CertName        string                                `json:"cert_name,omitempty" mapstructure:"cert_name" flag:"cert-name" desc:"The name of the certificate."`
	CertDescription string                                `json:"cert_description,omitempty" mapstructure:"cert_description" flag:"cert-description" desc:"The description of the certificate."`
	Metadata        IdsecSIACertificatesCertificateMetadata `json:"metadata" mapstructure:"metadata" flag:"metadata" desc:"The metadata of the certificate."`
	Labels          map[string]interface{}                `json:"labels,omitempty" mapstructure:"labels" flag:"labels" desc:"The additional labels assigned to the certificate."`
}
