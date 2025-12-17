package models

// IdsecSIACertificatesDeleteCertificate represents the input parameters for deleting a SIA certificate.
type IdsecSIACertificatesDeleteCertificate struct {
	CertificateID string `json:"certificate_id" mapstructure:"certificate_id" flag:"certificate-id" desc:"The ID of the certificate to delete."`
}
