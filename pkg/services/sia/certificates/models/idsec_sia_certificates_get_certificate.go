package models

// IdsecSIACertificatesGetCertificate represents the input parameters for retrieving a SIA certificate.
type IdsecSIACertificatesGetCertificate struct {
	CertificateID string `json:"certificate_id" mapstructure:"certificate_id" flag:"certificate-id" desc:"The ID of the certificate to retrieve."`
}
