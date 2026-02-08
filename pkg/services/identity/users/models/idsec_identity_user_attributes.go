package models

// IdsecIdentityUserAttributes represents the user attributes associated with a user.
type IdsecIdentityUserAttributes struct {
	UserID     string            `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"ID of the user"`
	Attributes map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of user attributes"`
}
