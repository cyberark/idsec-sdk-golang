package models

// IdsecSIADBGetStrongAccount is the struct for retrieving a strong account from the Idsec SIA DB.
type IdsecSIADBGetStrongAccount struct {
	StrongAccountID string `json:"strong_account_id" mapstructure:"strong_account_id" flag:"strong-account-id" validate:"required" desc:"The ID of the account to get."`
}
