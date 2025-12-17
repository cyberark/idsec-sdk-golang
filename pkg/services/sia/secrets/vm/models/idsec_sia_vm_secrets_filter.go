package models

// IdsecSIAVMSecretsFilter represents the request to filter secrets in a VM.
type IdsecSIAVMSecretsFilter struct {
	SecretType    string `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" flag:"secret-type" desc:"Type of secret to filter"`
	Name          string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"Name wildcard to filter with"`
	IsActive      string `json:"is_active,omitempty" mapstructure:"is_active,omitempty" flag:"is-active" desc:"Filter by active status: 'true' for active only, 'false' for inactive only, empty for all"`
	AccountDomain string `json:"account_domain,omitempty" mapstructure:"account_domain,omitempty" flag:"account-domain" desc:"Filter by account_domain in secret_details (supports regex pattern)"`
}
