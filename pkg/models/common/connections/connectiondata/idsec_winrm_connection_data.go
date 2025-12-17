package connectiondata

// IdsecWinRMConnectionData represents the connection data for a WinRM connection.
type IdsecWinRMConnectionData struct {
	CertificatePath  string `json:"certificate_path" mapstructure:"certificate_path"`
	TrustCertificate bool   `json:"trust_certificate" mapstructure:"trust_certificate"`
	Protocol         string `json:"protocol" mapstructure:"protocol"`
}
