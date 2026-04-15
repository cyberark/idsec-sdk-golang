package models

// IdsecSIADBUpdateStrongAccount is the struct for updating a strong account in the Idsec SIA DB.
type IdsecSIADBUpdateStrongAccount struct {
	StrongAccountID string `json:"strong_account_id" mapstructure:"strong_account_id" flag:"strong-account-id" desc:"The ID of the account to update."`
	StoreType       string `json:"store_type" mapstructure:"store_type" flag:"store-type" desc:"The store type of the account (managed,pam)." choices:"managed,pam"`
	Name            string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name of the account."`

	// Used in case the StoreType is pam
	Safe        string `json:"safe,omitempty" mapstructure:"safe" flag:"safe" desc:"The Safe of the account."`
	AccountName string `json:"account_name,omitempty" mapstructure:"account_name" flag:"account-name" desc:"The account name of the account."`

	// AccountProperties Fields
	Platform string `json:"platform,omitempty" mapstructure:"platform" flag:"platform" desc:"The platform of the account. The required propeties are dependent on the platform."`
	// Platform Specific Fields
	Address  string `json:"address,omitempty" mapstructure:"address" flag:"address" desc:"The address of the account."`
	Username string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"The username of the account."`
	Port     int    `json:"port,omitempty" mapstructure:"port" flag:"port" desc:"The port of the account."`
	Database string `json:"database,omitempty" mapstructure:"database" flag:"database" desc:"The database of the account."`
	DSN      string `json:"dsn,omitempty" mapstructure:"dsn" flag:"dsn" desc:"The DSN of the account."`

	// WinDomain Platform Specific Fields
	LogOnTo string `json:"log_on_to,omitempty" mapstructure:"log_on_to" flag:"log-on-to" desc:"The log on to field for WinDomain platform."`
	UserDN  string `json:"user_dn,omitempty" mapstructure:"user_dn" flag:"user-dn" desc:"The user DN field for WinDomain platform."`

	// AWS Platform Specific Fields
	AwsAccessKeyId      string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" flag:"aws-access-key-id" desc:"The AWS access key ID of the account."`
	AwsAccountId        string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" flag:"aws-account-id" desc:"The AWS account ID of the account."`
	AwsAccountAliasName string `json:"aws_account_alias_name,omitempty" mapstructure:"aws_account_alias_name" flag:"aws-account-alias-name" desc:"The AWS account alias name."`
	Region              string `json:"region,omitempty" mapstructure:"region" flag:"region" desc:"The AWS region." choices:"us-east-1,us-west-1,us-west-2,eu-west-1,eu-central-1,ap-northeast-1,ap-southeast-1,ap-southeast-2,sa-east-1,us-gov-west-1"`
	AuthDatabase        string `json:"auth_database,omitempty" mapstructure:"auth_database" flag:"auth-database" desc:"The authentication database of the account."`

	// MongoDB specific optional fields
	ReplicaSet string `json:"replica_set,omitempty" mapstructure:"replica_set" flag:"replica-set" desc:"The replica set name for MongoDB."`
	UseSSL     string `json:"use_ssl,omitempty" mapstructure:"use_ssl" flag:"use-ssl" desc:"The SSL usage setting for MongoDB."`

	// MSSql specific optional field
	ReconcileIsWinAccount bool `json:"reconcile_is_win_account,omitempty" mapstructure:"reconcile_is_win_account" flag:"reconcile-is-win-account" desc:"Whether to reconcile as Windows account for MSSql."`

	// PasswordSecretObject Fields
	Password        string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password of the account."`
	SecretAccessKey string `json:"secret_access_key,omitempty" mapstructure:"secret_access_key" flag:"secret-access-key" desc:"The Secret access key of the account."`
}
