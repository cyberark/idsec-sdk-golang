package models

// IdsecSIAVMSecretsFilter represents the request to filter secrets in a VM.
type IdsecSIAVMSecretsFilter struct {
	SecretType    string `json:"secret_type,omitempty" mapstructure:"secret_type,omitempty" flag:"secret-type" desc:"The type of Secret to filter."`
	Name          string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name of the wildcard to filter."`
	IsActive      string `json:"is_active,omitempty" mapstructure:"is_active,omitempty" flag:"is-active" desc:"Filter by active status: 'true' for active only, 'false' for inactive only, empty for all."`
	AccountDomain string `json:"account_domain,omitempty" mapstructure:"account_domain,omitempty" flag:"account-domain" desc:"Filter by account_domain in secret_details (supports regex pattern)."`
}
