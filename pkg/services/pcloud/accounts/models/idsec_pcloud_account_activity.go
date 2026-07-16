package models

// IdsecPCloudAccountActivity represents a single activity that was performed on an account.
type IdsecPCloudAccountActivity struct {
	Alert    bool   `json:"alert" mapstructure:"alert" desc:"Whether the activity triggered an alert" flag:"alert"`
	Date     int    `json:"date" mapstructure:"date" desc:"The date and time when the activity took place (UTC)" flag:"date"`
	User     string `json:"user" mapstructure:"user" desc:"The user who performed the activity" flag:"user"`
	Action   string `json:"action" mapstructure:"action" desc:"The activity that was performed" flag:"action"`
	ActionID int    `json:"action_id" mapstructure:"action_id" desc:"The ID of the activity that was performed" flag:"action-id"`
	ClientID string `json:"client_id" mapstructure:"client_id" desc:"The ID of the CyberArk client from which the user connected and performed the activity" flag:"client-id"`
	MoreInfo string `json:"more_info" mapstructure:"more_info" desc:"More information about the activity" flag:"more-info"`
	Reason   string `json:"reason" mapstructure:"reason" desc:"The reason given by the user for the activity" flag:"reason"`
}
