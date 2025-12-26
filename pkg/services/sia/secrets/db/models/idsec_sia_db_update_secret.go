package models

// IdsecSIADBUpdateSecret is the struct for updating a secret in the Idsec SIA DB.
type IdsecSIADBUpdateSecret struct {
	SecretID      string            `json:"secret_id,omitempty" mapstructure:"secret_id" flag:"secret-id" desc:"The Secret ID to update."`
	SecretName    string            `json:"secret_name,omitempty" mapstructure:"secret_name" flag:"secret-name" desc:"The name of the Secret to update."`
	NewSecretName string            `json:"new_secret_name,omitempty" mapstructure:"new_secret_name" flag:"new-secret-name" desc:"The new Secret name."`
	Description   string            `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"The description of the Secret to update."`
	Purpose       string            `json:"purpose,omitempty" mapstructure:"purpose" flag:"purpose" desc:"The purpose of the Secret to update."`
	Tags          map[string]string `json:"tags,omitempty" mapstructure:"tags" flag:"tags" desc:"The new tags of the Secret."`

	// Username Password Secret Type
	Username string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"The name or ID of the user for username_password type."`
	Password string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password of the user for username_password type."`

	// PAM Account Secret Type
	PAMSafe        string `json:"pam_safe,omitempty" mapstructure:"pam_safe" flag:"pam-safe" desc:"The Safe of the account for pam_account type."`
	PAMAccountName string `json:"pam_account_name,omitempty" mapstructure:"pam_account_name" flag:"pam-account-name" desc:"The account name for pam_account type."`

	// IAM Secret Type
	IAMAccount         string `json:"iam_account,omitempty" mapstructure:"iam_account" flag:"iam-account" desc:"The account number of the IAM user."`
	IAMUsername        string `json:"iam_username,omitempty" mapstructure:"iam_username" flag:"iam-username" desc:"The username portion in the ARN of the IAM user."`
	IAMAccessKeyID     string `json:"iam_access_key_id,omitempty" mapstructure:"iam_access_key_id" flag:"iam-access-key-id" desc:"The access key ID of the user."`
	IAMSecretAccessKey string `json:"iam_secret_access_key,omitempty" mapstructure:"iam_secret_access_key" flag:"iam-secret-access-key" desc:"The secret access key of the user."`

	// Atlas Secret Type
	AtlasPublicKey  string `json:"atlas_public_key,omitempty" mapstructure:"atlas_public_key" flag:"atlas-public-key" desc:"The public part of MongoDB Atlas access keys."`
	AtlasPrivateKey string `json:"atlas_private_key,omitempty" mapstructure:"atlas_private_key" flag:"atlas-private-key" desc:"The private part of MongoDB Atlas access keys."`
}

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

	AwsAccessKeyId string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" flag:"aws-access-key-id" desc:"The AWS access key ID of the account."`
	AwsAccountId   string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" flag:"aws-account-id" desc:"The AWS account ID of the account."`
	AuthDatabase   string `json:"auth_database,omitempty" mapstructure:"auth_database" flag:"auth-database" desc:"The authentication database of the account."`

	// PasswordSecretObject Fields
	Password        string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"The password of the account."`
	SecretAccessKey string `json:"secret_access_key,omitempty" mapstructure:"secret_access_key" flag:"secret-access-key" desc:"The Secret access key of the account."`
}
