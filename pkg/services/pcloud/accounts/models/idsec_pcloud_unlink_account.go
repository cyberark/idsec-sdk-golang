package models

// IdsecPCloudUnlinkAccount represents the details required to unlink an account from a source account.
type IdsecPCloudUnlinkAccount struct {
	AccountID          string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account to unlink from the source" flag:"account-id" validate:"required"`
	ExtraPasswordIndex string `json:"extra_password_index" mapstructure:"extra_password_index" desc:"The linked account's extra password index. The index can be for a Reconcile/Logon/Other account defined in the platform" flag:"extra-password-index" validate:"required"`
}
