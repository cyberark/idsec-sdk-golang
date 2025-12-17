package models

// IdsecPCloudDeleteAccount represents the details required to delete an account.
type IdsecPCloudDeleteAccount struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The id of the account to delete" flag:"account-id" validate:"required"`
}
