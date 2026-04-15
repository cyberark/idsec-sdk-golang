package models

// IdsecSIADBDeleteStrongAccount is the struct for deleting a strong account from the Idsec SIA DB.
type IdsecSIADBDeleteStrongAccount struct {
	StrongAccountID string `json:"strong_account_id" mapstructure:"strong_account_id" flag:"strong-account-id" validate:"required" desc:"The ID of the account to delete."`
}
