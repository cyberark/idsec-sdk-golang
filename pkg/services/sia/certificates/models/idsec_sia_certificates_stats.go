package models

// IdsecSIACertificatesStats represents statistics about SIA certificates.
type IdsecSIACertificatesStats struct {
	CertificatesCount int `json:"certificates_count" mapstructure:"certificates_count" desc:"Total number of SIA certificates."`
}
