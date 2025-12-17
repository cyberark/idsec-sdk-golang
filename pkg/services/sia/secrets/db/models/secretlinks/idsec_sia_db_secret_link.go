package secretlinks

// IdsecSIADBSecretLink represents a secret link in the Idsec SIA DB.
type IdsecSIADBSecretLink interface {
	// GetLinkSecretType returns the secret type of the secret link.
	GetLinkSecretType() string
}
