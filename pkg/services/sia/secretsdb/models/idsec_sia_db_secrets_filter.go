package models

// IdsecSIADBSecretsFilter represents the filters for querying secrets in the Idsec SIA DB.
type IdsecSIADBSecretsFilter struct {
	SecretName string            `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"Indicates whether to filter by Secret name."`
	SecretType string            `json:"secret_type,omitempty" mapstructure:"secret_type" flag:"secret-type" choices:"username_password,iam_user,cyberark_pam,atlas_access_keys" desc:"Indicated whether to filter by type."`
	StoreType  string            `json:"store_type,omitempty" mapstructure:"store_type" flag:"store-type" desc:"Indicates whether to filter by store type."`
	IsActive   bool              `json:"is_active,omitempty" mapstructure:"is_active" flag:"is-active" desc:"Indicates whether to filter by active Secrets."`
	Tags       map[string]string `json:"tags,omitempty" mapstructure:"tags" flag:"tags" desc:"Indicates whether to filter by tags."`
}
