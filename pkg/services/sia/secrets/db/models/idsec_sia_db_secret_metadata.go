package models

// IdsecSIADBSecretMetadata represents the metadata of a secret in the Idsec SIA DB.
type IdsecSIADBSecretMetadata struct {
	SecretID          string                  `json:"secret_id" mapstructure:"secret_id" desc:"The Secret identifier."`
	SecretName        string                  `json:"secret_name" mapstructure:"secret_name" desc:"The name of the Secret."`
	Description       string                  `json:"description,omitempty" mapstructure:"description" desc:"The description of the Secret."`
	Purpose           string                  `json:"purpose,omitempty" mapstructure:"purpose" desc:"The purpose of the Secret."`
	SecretType        string                  `json:"secret_type" mapstructure:"secret_type" desc:"The type of the Secret." choices:"username_password,iam_user,cyberark_pam,atlas_access_keys"`
	SecretStore       IdsecSIADBStoreDescriptor `json:"secret_store" mapstructure:"secret_store" desc:"The Secret store details of the Secret."`
	SecretLink        map[string]interface{}  `json:"secret_link,omitempty" mapstructure:"secret_link" desc:"The link details of the Secret."`
	SecretExposedData map[string]interface{}  `json:"secret_exposed_data,omitempty" mapstructure:"secret_exposed_data" desc:"The portion of the Secret data which can be exposed to the user."`
	Tags              map[string]string       `json:"tags,omitempty" mapstructure:"tags" desc:"The tags of the Secret."`
	CreatedBy         string                  `json:"created_by" mapstructure:"created_by" desc:"The creator the Secret."`
	CreationTime      string                  `json:"creation_time" mapstructure:"creation_time" desc:"The creation time of the Secret."`
	LastUpdatedBy     string                  `json:"last_updated_by" mapstructure:"last_updated_by" desc:"The last user who updated the Secret."`
	LastUpdateTime    string                  `json:"last_update_time" mapstructure:"last_update_time" desc:"The time the Secret was last updated."`
	IsActive          bool                    `json:"is_active" mapstructure:"is_active" desc:"Indicates whether the Secret is active or not."`
}


type IdsecSIADBSecretMetadataList struct {
	TotalCount int                      `json:"total_count" mapstructure:"total_count" desc:"The total number of Secrets found."`
	Secrets    []IdsecSIADBSecretMetadata `json:"secrets" mapstructure:"secrets" desc:"The Secrets actual metadata."`
}

// IdsecSIADBDatabaseStrongAccount represents the response when getting a strong account.
type IdsecSIADBDatabaseStrongAccount struct {
	ID         string `json:"id" mapstructure:"id" desc:"The account identifier."`
	Name       string `json:"name" mapstructure:"name" desc:"The account name."`
	StoreType  string `json:"store_type" mapstructure:"store_type" desc:"The type of store: pam or managed." choices:"pam,managed"`
	ModifiedAt string `json:"modified_at" mapstructure:"modified_at" desc:"The last modification timestamp."`
	CreatedAt  string `json:"created_at" mapstructure:"created_at" desc:"The creation timestamp."`
	CreatedBy  string `json:"created_by" mapstructure:"created_by" desc:"The user who created the account."`
	ModifiedBy string `json:"modified_by" mapstructure:"modified_by" desc:"The user who last modified the account."`

	// Used in case the StoreType is pam
	Safe        string `json:"safe,omitempty" mapstructure:"safe" desc:"The Safe of the account."`
	AccountName string `json:"account_name,omitempty" mapstructure:"account_name" desc:"The account name of the account."`

	// AccountProperties Fields
	Platform string `json:"platform,omitempty" mapstructure:"platform" desc:"The alatform of the account. The required propeties are dependent on the platform." choices:"PostgreSQL,MySQL,MariaDB,MSSql,Oracle,MongoDB,DB2UnixSSH,WinDomain,AWSAccessKeys"`
	// Platform Specific Fields
	Address  string `json:"address,omitempty" mapstructure:"address" desc:"The address of the account."`
	Username string `json:"username,omitempty" mapstructure:"username" desc:"The username of the account."`
	Port     int    `json:"port,omitempty" mapstructure:"port" desc:"The port of the account."`
	Database string `json:"database,omitempty" mapstructure:"database" desc:"The database of the account."`
	DSN      string `json:"dsn,omitempty" mapstructure:"dsn" desc:"The DSN of the account."`

	AwsAccessKeyId string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" desc:"The AWS access key ID of the account."`
	AwsAccountId   string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" desc:"The AWS access key ID of the account."`
	AuthDatabase   string `json:"auth_database,omitempty" mapstructure:"auth_database" desc:"The authentication database of the account."`
}

// IdsecSIADBListStrongAccounts represents the request parameters for listing database strong accounts.
// Supports pagination with cursor and limit.
type IdsecSIADBListStrongAccounts struct {
	Cursor string `json:"cursor,omitempty" mapstructure:"cursor" flag:"cursor" desc:"The pagination cursor from previous response (default: empty string)."`
	Limit  *int   `json:"limit,omitempty" mapstructure:"limit" flag:"limit" desc:"The maximum number of items to return (default: 500, min: 1, max: 1000)."`
}

// IdsecSIADBDatabaseStrongAccountsList contains the list of database strong accounts.
type IdsecSIADBDatabaseStrongAccountsList struct {
	Items      []IdsecSIADBDatabaseStrongAccount `json:"items" mapstructure:"items" desc:"The list of database strong accounts."`
	NextCursor string                            `json:"next_cursor,omitempty" mapstructure:"next_cursor" desc:"The cursor for pagination (default: empty string, empty if no more results)."`
}
