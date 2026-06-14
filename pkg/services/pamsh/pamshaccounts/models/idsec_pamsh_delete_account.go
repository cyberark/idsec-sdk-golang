package models

// IdsecPamshDeleteAccount represents the details required to delete an account.
type IdsecPamshDeleteAccount struct {
	AccountID string `json:"id" mapstructure:"id" desc:"The unique ID of the account to delete" flag:"account-id" validate:"required"`
}
