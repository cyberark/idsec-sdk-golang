package models

// IdsecPCloudListAccountActivities represents the details required to list an account's activities.
type IdsecPCloudListAccountActivities struct {
	AccountID string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the activities" flag:"account-id" validate:"required"`
}
