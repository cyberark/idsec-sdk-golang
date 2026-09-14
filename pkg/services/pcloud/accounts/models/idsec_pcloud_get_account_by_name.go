package models

// IdsecPCloudGetAccountByName represents the details required to get an account by its name.
type IdsecPCloudGetAccountByName struct {
	AccountName string `json:"account_name" mapstructure:"account_name" desc:"The name of the account to retrieve" flag:"account-name" validate:"required"`
}
