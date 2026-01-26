package models

// IdsecPCloudLinkAccount represents the details required to link an account to a source account.
type IdsecPCloudLinkAccount struct {
	AccountID          string `json:"account_id" mapstructure:"account_id" desc:"The ID of the linked account" flag:"account-id" validate:"required"`
	Safe               string `json:"safe" mapstructure:"safe" desc:"The Safe in which the linked account is stored" flag:"safe" validate:"required"`
	ExtraPasswordIndex int    `json:"extra_password_index" mapstructure:"extra_password_index" desc:"The linked account's extra password index. The index can be for a Reconcile/Logon/Other account defined in the platform" flag:"extra-password-index" validate:"required"`
	Folder             string `json:"folder" mapstructure:"folder" desc:"The folder in which the linked account is stored" flag:"folder" validate:"required"`
	Name               string `json:"name" mapstructure:"name" desc:"Name of the linked account" flag:"name" validate:"required"`
}
