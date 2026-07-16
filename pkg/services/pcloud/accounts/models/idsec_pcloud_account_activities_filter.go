package models

// IdsecPCloudAccountActivitiesFilter represents the filter options for an account's activities.
type IdsecPCloudAccountActivitiesFilter struct {
	AccountID      string `json:"account_id" mapstructure:"account_id" flag:"account-id" desc:"The ID of the account for which to retrieve the activities" validate:"required"`
	User           string `json:"user,omitempty" mapstructure:"user,omitempty" flag:"user" desc:"Only return activities performed by this user"`
	ActionContains string `json:"action_contains,omitempty" mapstructure:"action_contains,omitempty" flag:"action-contains" desc:"Only return activities whose action contains this string"`
	ClientID       string `json:"client_id,omitempty" mapstructure:"client_id,omitempty" flag:"client-id" desc:"Only return activities performed from this CyberArk client ID"`
	AlertsOnly     bool   `json:"alerts_only,omitempty" mapstructure:"alerts_only,omitempty" flag:"alerts-only" desc:"Only return activities that triggered an alert" default:"false"`
	FromDate       int    `json:"from_date,omitempty" mapstructure:"from_date,omitempty" flag:"from-date" desc:"Only return activities that occurred on or after this Unix timestamp (UTC)"`
	ToDate         int    `json:"to_date,omitempty" mapstructure:"to_date,omitempty" flag:"to-date" desc:"Only return activities that occurred on or before this Unix timestamp (UTC)"`
}
