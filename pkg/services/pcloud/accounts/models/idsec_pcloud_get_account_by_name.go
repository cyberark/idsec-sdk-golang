package models

// IdsecPCloudGetAccountByName represents the details required to get an account by its name.
type IdsecPCloudGetAccountByName struct {
	AccountName string `json:"account_name" mapstructure:"account_name" desc:"The name of the account to retrieve" flag:"account-name" validate:"required"`
	SafeName    string `json:"safe_name,omitempty" mapstructure:"safe_name,omitempty" desc:"The name of the Safe that holds the account. If omitted, the first account with this name in any Safe is returned" flag:"safe-name"`
}
