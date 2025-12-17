package models

// IdsecSIADBSecretMetadata represents the metadata of a secret in the Idsec SIA DB.
type IdsecSIADBSecretMetadata struct {
	SecretID          string                    `json:"secret_id" mapstructure:"secret_id" desc:"Secret identifier"`
	SecretName        string                    `json:"secret_name" mapstructure:"secret_name" desc:"Name of the secret"`
	Description       string                    `json:"description,omitempty" mapstructure:"description" desc:"Description about the secret"`
	Purpose           string                    `json:"purpose,omitempty" mapstructure:"purpose" desc:"Purpose of the secret"`
	SecretType        string                    `json:"secret_type" mapstructure:"secret_type" desc:"Type of the secret" choices:"username_password,iam_user,cyberark_pam,atlas_access_keys"`
	SecretStore       IdsecSIADBStoreDescriptor `json:"secret_store" mapstructure:"secret_store" desc:"Secret store details of the secret"`
	SecretLink        map[string]interface{}    `json:"secret_link,omitempty" mapstructure:"secret_link" desc:"Link details of the secret"`
	SecretExposedData map[string]interface{}    `json:"secret_exposed_data,omitempty" mapstructure:"secret_exposed_data" desc:"Portion of the secret data which can be exposed to the user"`
	Tags              map[string]string         `json:"tags,omitempty" mapstructure:"tags" desc:"Tags of the secret"`
	CreatedBy         string                    `json:"created_by" mapstructure:"created_by" desc:"Who created the secret"`
	CreationTime      string                    `json:"creation_time" mapstructure:"creation_time" desc:"Creation time of the secret"`
	LastUpdatedBy     string                    `json:"last_updated_by" mapstructure:"last_updated_by" desc:"Who last updated the secret"`
	LastUpdateTime    string                    `json:"last_update_time" mapstructure:"last_update_time" desc:"When was the secret last updated"`
	IsActive          bool                      `json:"is_active" mapstructure:"is_active" desc:"Whether the secret is active or not"`
}

type IdsecSIADBSecretMetadataList struct {
	TotalCount int                        `json:"total_count" mapstructure:"total_count" desc:"Total secrets found"`
	Secrets    []IdsecSIADBSecretMetadata `json:"secrets" mapstructure:"secrets" desc:"Actual secrets metadata"`
}

// IdsecSIADBDatabaseStrongAccount represents the response when getting a strong account.
type IdsecSIADBDatabaseStrongAccount struct {
	ID         string `json:"id" mapstructure:"id" desc:"Account identifier"`
	Name       string `json:"name" mapstructure:"name" desc:"Account name"`
	StoreType  string `json:"store_type" mapstructure:"store_type" desc:"Type of store: pam or managed" choices:"pam,managed"`
	ModifiedAt string `json:"modified_at" mapstructure:"modified_at" desc:"Last modification timestamp"`
	CreatedAt  string `json:"created_at" mapstructure:"created_at" desc:"Creation timestamp"`
	CreatedBy  string `json:"created_by" mapstructure:"created_by" desc:"User who created the account"`
	ModifiedBy string `json:"modified_by" mapstructure:"modified_by" desc:"User who last modified the account"`

	// Used in case the StoreType is pam
	Safe        string `json:"safe,omitempty" mapstructure:"safe" desc:"Safe of the account"`
	AccountName string `json:"account_name,omitempty" mapstructure:"account_name" desc:"Account name of the account"`

	// AccountProperties Fields
	Platform string `json:"platform,omitempty" mapstructure:"platform" desc:"Platform of the account, The required Propeties are dependent on the platform" choices:"PostgreSQL,MySQL,MariaDB,MSSql,Oracle,MongoDB,DB2UnixSSH,WinDomain,AWSAccessKeys"`
	// Platform Specific Fields
	Address  string `json:"address,omitempty" mapstructure:"address" desc:"Address of the account"`
	Username string `json:"username,omitempty" mapstructure:"username" desc:"Username of the account"`
	Port     int    `json:"port,omitempty" mapstructure:"port" desc:"Port of the account"`
	Database string `json:"database,omitempty" mapstructure:"database" desc:"Database of the account"`
	DSN      string `json:"dsn,omitempty" mapstructure:"dsn" desc:"DSN of the account"`

	AwsAccessKeyId string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" desc:"AWS Access Key ID of the account"`
	AwsAccountId   string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" desc:"AWS Access Key ID of the account"`
	AuthDatabase   string `json:"auth_database,omitempty" mapstructure:"auth_database" desc:"Authentication database of the account"`
}

// IdsecSIADBListStrongAccounts represents the request parameters for listing database strong accounts.
// Supports pagination with cursor and limit.
type IdsecSIADBListStrongAccounts struct {
	Cursor string `json:"cursor,omitempty" mapstructure:"cursor" flag:"cursor" desc:"Pagination cursor from previous response (default: empty string)"`
	Limit  *int   `json:"limit,omitempty" mapstructure:"limit" flag:"limit" desc:"Maximum number of items to return (default: 500, min: 1, max: 1000)"`
}

// IdsecSIADBDatabaseStrongAccountsList contains the list of database strong accounts.
type IdsecSIADBDatabaseStrongAccountsList struct {
	Items      []IdsecSIADBDatabaseStrongAccount `json:"items" mapstructure:"items" desc:"List of database strong accounts"`
	NextCursor string                            `json:"next_cursor,omitempty" mapstructure:"next_cursor" desc:"Cursor for pagination (default: empty string, empty if no more results)"`
}
