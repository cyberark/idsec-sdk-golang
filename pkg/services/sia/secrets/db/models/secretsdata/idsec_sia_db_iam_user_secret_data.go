package secretsdata

// IdsecSIADBIAMUserSecretData represents the IAM user secret data in the Idsec SIA DB.
type IdsecSIADBIAMUserSecretData struct {
	IdsecSIADBSecretData
	Account         string                 `json:"account" mapstructure:"account" desc:"Account number of the iam user"`
	Region          string                 `json:"region,omitempty" mapstructure:"region" desc:"Region associated with the iam user"`
	Username        string                 `json:"username" mapstructure:"username" desc:"Username portion in the ARN of the iam user"`
	AccessKeyID     string                 `json:"access_key_id" mapstructure:"access_key_id" desc:"Access key id of the user"`
	SecretAccessKey string                 `json:"secret_access_key" mapstructure:"secret_access_key" desc:"Secret access key of the user"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" mapstructure:"metadata" desc:"Extra secret details"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBIAMUserSecretData) GetDataSecretType() string {
	return "iam_user"
}

// IdsecSIADBExposedIAMUserSecretData represents the exposed IAM user secret data in the Idsec SIA DB.
type IdsecSIADBExposedIAMUserSecretData struct {
	IdsecSIADBSecretData
	Account  string `json:"account" mapstructure:"account" desc:"Account number of the iam user"`
	Username string `json:"username" mapstructure:"username" desc:"Username portion in the ARN of the iam user"`
}

// GetDataSecretType returns the secret type of the secret data.
func (s *IdsecSIADBExposedIAMUserSecretData) GetDataSecretType() string {
	return "iam_user"
}
