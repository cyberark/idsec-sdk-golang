package secretsdata

// IdsecSIADBSecretData represents a secret data in the Idsec SIA DB.
type IdsecSIADBSecretData interface {
	// GetDataSecretType returns the secret type of the secret data.
	GetDataSecretType() string
}
