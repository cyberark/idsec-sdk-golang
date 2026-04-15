package models

// IdsecSIADBSecretMetadata represents the metadata of a secret in the Idsec SIA DB.
// Deprecated: Use the db-strong-accounts resource instead.
type IdsecSIADBSecretMetadata struct {
	SecretID          string                    `json:"secret_id" mapstructure:"secret_id" desc:"The Secret identifier."`
	SecretName        string                    `json:"secret_name" mapstructure:"secret_name" desc:"The name of the Secret."`
	Description       string                    `json:"description,omitempty" mapstructure:"description" desc:"The description of the Secret."`
	Purpose           string                    `json:"purpose,omitempty" mapstructure:"purpose" desc:"The purpose of the Secret."`
	SecretType        string                    `json:"secret_type" mapstructure:"secret_type" desc:"The type of the Secret." choices:"username_password,iam_user,cyberark_pam,atlas_access_keys"`
	SecretStore       IdsecSIADBStoreDescriptor `json:"secret_store" mapstructure:"secret_store" desc:"The Secret store details of the Secret."`
	SecretLink        map[string]interface{}    `json:"secret_link,omitempty" mapstructure:"secret_link" desc:"The link details of the Secret."`
	SecretExposedData map[string]interface{}    `json:"secret_exposed_data,omitempty" mapstructure:"secret_exposed_data" desc:"The portion of the Secret data which can be exposed to the user."`
	Tags              map[string]string         `json:"tags,omitempty" mapstructure:"tags" desc:"The tags of the Secret."`
	CreatedBy         string                    `json:"created_by" mapstructure:"created_by" desc:"The creator the Secret."`
	CreationTime      string                    `json:"creation_time" mapstructure:"creation_time" desc:"The creation time of the Secret."`
	LastUpdatedBy     string                    `json:"last_updated_by" mapstructure:"last_updated_by" desc:"The last user who updated the Secret."`
	LastUpdateTime    string                    `json:"last_update_time" mapstructure:"last_update_time" desc:"The time the Secret was last updated."`
	IsActive          bool                      `json:"is_active" mapstructure:"is_active" desc:"Indicates whether the Secret is active or not."`
}

// IdsecSIADBSecretMetadataList represents a list of secrets.
// Deprecated: Use the db-strong-accounts resource instead.
type IdsecSIADBSecretMetadataList struct {
	TotalCount int                        `json:"total_count" mapstructure:"total_count" desc:"The total number of Secrets found."`
	Secrets    []IdsecSIADBSecretMetadata `json:"secrets" mapstructure:"secrets" desc:"The Secrets actual metadata."`
}
