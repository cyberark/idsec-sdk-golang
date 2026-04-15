package models

// IdsecSIADBStrongAccount represents the response when getting a strong account.
type IdsecSIADBStrongAccount struct {
	StrongAccountID string `json:"strong_account_id" mapstructure:"strong_account_id" desc:"The account identifier."`
	Name            string `json:"name" mapstructure:"name" desc:"The account name."`
	StoreType       string `json:"store_type" mapstructure:"store_type" desc:"The type of store: pam or managed." choices:"pam,managed"`
	ModifiedAt      string `json:"modified_at" mapstructure:"modified_at" desc:"The last modification timestamp."`
	CreatedAt       string `json:"created_at" mapstructure:"created_at" desc:"The creation timestamp."`
	CreatedBy       string `json:"created_by" mapstructure:"created_by" desc:"The user who created the account."`
	ModifiedBy      string `json:"modified_by" mapstructure:"modified_by" desc:"The user who last modified the account."`

	// Used in case the StoreType is pam
	Safe        string `json:"safe,omitempty" mapstructure:"safe" desc:"The Safe of the account."`
	AccountName string `json:"account_name,omitempty" mapstructure:"account_name" desc:"The account name of the account."`

	// AccountProperties Fields
	Platform string `json:"platform,omitempty" mapstructure:"platform" desc:"The platform of the account. The required propeties are dependent on the platform." choices:"PostgreSQL,MySQL,MariaDB,MSSql,Oracle,MongoDB,DB2UnixSSH,WinDomain,AWSAccessKeys"`
	// Platform Specific Fields
	Address  string `json:"address,omitempty" mapstructure:"address" desc:"The address of the account."`
	Username string `json:"username,omitempty" mapstructure:"username" desc:"The username of the account."`
	Port     int    `json:"port,omitempty" mapstructure:"port" desc:"The port of the account."`
	Database string `json:"database,omitempty" mapstructure:"database" desc:"The database of the account."`
	DSN      string `json:"dsn,omitempty" mapstructure:"dsn" desc:"The DSN of the account."`

	// WinDomain Platform Specific Fields
	LogOnTo string `json:"log_on_to,omitempty" mapstructure:"log_on_to" desc:"The log on to field for WinDomain platform."`
	UserDN  string `json:"user_dn,omitempty" mapstructure:"user_dn" desc:"The user DN field for WinDomain platform."`

	// AWS Platform Specific Fields
	AwsAccessKeyId      string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" desc:"The AWS access key ID of the account."`
	AwsAccountId        string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" desc:"The AWS access key ID of the account."`
	AwsAccountAliasName string `json:"aws_account_alias_name,omitempty" mapstructure:"aws_account_alias_name" desc:"The AWS account alias name."`
	Region              string `json:"region,omitempty" mapstructure:"region" desc:"The AWS region." choices:"us-east-1,us-west-1,us-west-2,eu-west-1,eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1,us-gov-west-1"`
	AuthDatabase        string `json:"auth_database,omitempty" mapstructure:"auth_database" desc:"The authentication database of the account."`

	// MongoDB specific optional fields
	ReplicaSet string `json:"replica_set,omitempty" mapstructure:"replica_set" desc:"The replica set name for MongoDB."`
	UseSSL     string `json:"use_ssl,omitempty" mapstructure:"use_ssl" desc:"The SSL usage setting for MongoDB."`

	// MSSql specific optional field
	ReconcileIsWinAccount bool `json:"reconcile_is_win_account,omitempty" mapstructure:"reconcile_is_win_account" desc:"Whether to reconcile as Windows account for MSSql."`
}

// IdsecSIADBStrongAccountsList represents the API response for listing strong accounts with cursor-based pagination.
type IdsecSIADBStrongAccountsList struct {
	TotalCount int                       `json:"total_count" mapstructure:"total_count" desc:"The total number of strong accounts found."`
	Items      []IdsecSIADBStrongAccount `json:"items" mapstructure:"items" desc:"The list of database strong accounts."`
	NextCursor string                    `json:"next_cursor,omitempty" mapstructure:"next_cursor" desc:"The cursor for pagination (default: empty string, empty if no more results)."`
}
