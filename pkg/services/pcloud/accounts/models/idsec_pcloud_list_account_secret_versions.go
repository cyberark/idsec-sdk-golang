package models

// IdsecPCloudListAccountSecretVersions represents the details required to list account secret versions.
type IdsecPCloudListAccountSecretVersions struct {
	AccountID     string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the secrets versions" flag:"account-id" validate:"required"`
	ShowTemporary bool   `json:"show_temporary" mapstructure:"show_temporary" desc:"Whether to return both permanent and temporary secret versions or only permanent versions" flag:"show-temporary" default:"false"`
}
