package models

// IdsecSIADBAddSecret is the struct for adding a secret to the Idsec SIA DB.
// Deprecated: Use the db-strong-accounts resource instead.
type IdsecSIADBAddSecret struct {
	SecretName  string            `json:"secret_name" mapstructure:"secret_name" flag:"secret-name" validate:"required" desc:"The name of the Secret."`
	Description string            `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"The description of the Secret."`
	Purpose     string            `json:"purpose,omitempty" mapstructure:"purpose" flag:"purpose" desc:"The purpose of the Secret."`
	SecretType  string            `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" validate:"required" desc:"The type of Secret (username_password, iam_user, cyberark_pam, atlas_access_keys)." choices:"username_password,iam_user,cyberark_pam,atlas_access_keys"`
	StoreType   string            `json:"store_type,omitempty" mapstructure:"store_type" flag:"store-type" desc:"The store type of the Secret (managed, pam), will be deduced by the Secret type, if not provided." choices:"managed,pam"`
	Tags        map[string]string `json:"tags,omitempty" mapstructure:"tags" flag:"tags" desc:"The tags of the Secret."`

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
	IAMSecretAccessKey string `json:"iam_secret_access_key,omitempty" mapstructure:"iam_secret_access_key" flag:"iam-secret-access-key" desc:"The Secret access key of the user."`

	// Atlas Secret Type
	AtlasPublicKey  string `json:"atlas_public_key,omitempty" mapstructure:"atlas_public_key" flag:"atlas-public-key" desc:"The public part of MongoDB Atlas access keys."`
	AtlasPrivateKey string `json:"atlas_private_key,omitempty" mapstructure:"atlas_private_key" flag:"atlas-private-key" desc:"The private part of MongoDB Atlas access keys."`
}
