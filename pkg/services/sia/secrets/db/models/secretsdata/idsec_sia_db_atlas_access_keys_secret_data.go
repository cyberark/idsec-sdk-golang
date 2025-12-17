package secretsdata

// IdsecSIADBAtlasAccessKeysSecretData represents the Mongo Atlas access keys secret data in the Idsec SIA DB.
type IdsecSIADBAtlasAccessKeysSecretData struct {
	IdsecSIADBSecretData
	PublicKey  string                 `json:"public_key" mapstructure:"public_key" desc:"Public part of mongo atlas access keys"`
	PrivateKey string                 `json:"private_key" mapstructure:"private_key" desc:"Private part of mongo atlas access keys"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" mapstructure:"metadata" desc:"Extra secret details"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBAtlasAccessKeysSecretData) GetDataSecretType() string {
	return "atlas_access_keys"
}

// IdsecSIADBExposedAtlasAccessKeysSecretData represents the exposed Mongo Atlas access keys secret data in the Idsec SIA DB.
type IdsecSIADBExposedAtlasAccessKeysSecretData struct {
	IdsecSIADBSecretData
	PublicKey string `json:"public_key" mapstructure:"public_key" desc:"Public part of mongo atlas access keys"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBExposedAtlasAccessKeysSecretData) GetDataSecretType() string {
	return "atlas_access_keys"
}
