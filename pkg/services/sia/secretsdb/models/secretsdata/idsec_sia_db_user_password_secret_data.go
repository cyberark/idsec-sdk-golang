package secretsdata

// IdsecSIADBUserPasswordSecretData represents the user password secret data in the Idsec SIA DB.
type IdsecSIADBUserPasswordSecretData struct {
	IdsecSIADBSecretData
	Username string                 `json:"username,omitempty" mapstructure:"username" desc:"Name or id of the user"`
	Password string                 `json:"password,omitempty" mapstructure:"password" desc:"Password of the user"`
	Metadata map[string]interface{} `json:"metadata,omitempty" mapstructure:"metadata" desc:"Extra secret details"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBUserPasswordSecretData) GetDataSecretType() string {
	return "username_password"
}

// IdsecSIADBExposedUserPasswordSecretData represents the exposed user password secret data in the Idsec SIA DB.
type IdsecSIADBExposedUserPasswordSecretData struct {
	IdsecSIADBSecretData
	Username string `json:"username,omitempty" mapstructure:"username" desc:"Name or id of the user"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBExposedUserPasswordSecretData) GetDataSecretType() string {
	return "username_password"
}
