package models

// IdsecSIADBAddSecret is the struct for adding a secret to the Idsec SIA DB.
type IdsecSIADBAddSecret struct {
	SecretName  string            `json:"secret_name" mapstructure:"secret_name" flag:"secret-name" validate:"required" desc:"Name of the secret"`
	Description string            `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description about the secret"`
	Purpose     string            `json:"purpose,omitempty" mapstructure:"purpose" flag:"purpose" desc:"Purpose of the secret"`
	SecretType  string            `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" validate:"required" desc:"Type of the secret (username_password,iam_user,cyberark_pam,atlas_access_keys)" choices:"username_password,iam_user,cyberark_pam,atlas_access_keys"`
	StoreType   string            `json:"store_type,omitempty" mapstructure:"store_type" flag:"store-type" desc:"Store type of the secret (managed,pam), will be deduced by the secret type if not given" choices:"managed,pam"`
	Tags        map[string]string `json:"tags,omitempty" mapstructure:"tags" flag:"tags" desc:"Tags of the secret"`

	// Username Password Secret Type
	Username string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"Name or id of the user for username_password type"`
	Password string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"Password of the user for username_password type"`

	// PAM Account Secret Type
	PAMSafe        string `json:"pam_safe,omitempty" mapstructure:"pam_safe" flag:"pam-safe" desc:"Safe of the account for pam_account type"`
	PAMAccountName string `json:"pam_account_name,omitempty" mapstructure:"pam_account_name" flag:"pam-account-name" desc:"Account name for pam_account type"`

	// IAM Secret Type
	IAMAccount         string `json:"iam_account,omitempty" mapstructure:"iam_account" flag:"iam-account" desc:"Account number of the iam user"`
	IAMUsername        string `json:"iam_username,omitempty" mapstructure:"iam_username" flag:"iam-username" desc:"Username portion in the ARN of the iam user"`
	IAMAccessKeyID     string `json:"iam_access_key_id,omitempty" mapstructure:"iam_access_key_id" flag:"iam-access-key-id" desc:"Access key id of the user"`
	IAMSecretAccessKey string `json:"iam_secret_access_key,omitempty" mapstructure:"iam_secret_access_key" flag:"iam-secret-access-key" desc:"Secret access key of the user"`

	// Atlas Secret Type
	AtlasPublicKey  string `json:"atlas_public_key,omitempty" mapstructure:"atlas_public_key" flag:"atlas-public-key" desc:"Public part of mongo atlas access keys"`
	AtlasPrivateKey string `json:"atlas_private_key,omitempty" mapstructure:"atlas_private_key" flag:"atlas-private-key" desc:"Private part of mongo atlas access keys"`
}

// IdsecSIADBAddStrongAccount is the struct for adding a strong account to the Idsec SIA DB.
type IdsecSIADBAddStrongAccount struct {
	StoreType string `json:"store_type" mapstructure:"store_type" flag:"store-type" desc:"Store type of the account (managed,pam)" choices:"managed,pam"`
	Name      string `json:"name" mapstructure:"name" flag:"name" desc:"Name of the account"`

	// Used in case the StoreType is pam
	Safe        string `json:"safe,omitempty" mapstructure:"safe" flag:"safe" desc:"Safe of the account"`
	AccountName string `json:"account_name,omitempty" mapstructure:"account_name" flag:"account-name" desc:"Account name of the account"`

	// AccountProperties Fields
	Platform string `json:"platform,omitempty" mapstructure:"platform" flag:"platform" desc:"Platform of the account, The required Propeties are dependent on the platform"`

	Address  string `json:"address,omitempty" mapstructure:"address" flag:"address" desc:"Address of the account"`
	Username string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"Username of the account"`
	Port     int    `json:"port,omitempty" mapstructure:"port" flag:"port" desc:"Port of the account"`
	Database string `json:"database,omitempty" mapstructure:"database" flag:"database" desc:"Database of the account"`

	AwsAccessKeyId string `json:"aws_access_key_id,omitempty" mapstructure:"aws_access_key_id" flag:"aws-access-key-id" desc:"AWS Access Key ID of the account"`
	AwsAccountId   string `json:"aws_account_id,omitempty" mapstructure:"aws_account_id" flag:"aws-account-id" desc:"AWS Account ID of the account"`
	AuthDatabase   string `json:"auth_database,omitempty" mapstructure:"auth_database" flag:"auth-database" desc:"Authentication database of the account"`

	// PasswordSecretObject Fields
	Password        string `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"Password of the account"`
	SecretAccessKey string `json:"secret_access_key,omitempty" mapstructure:"secret_access_key" flag:"secret-access-key" desc:"Secret access key of the account"`
}
