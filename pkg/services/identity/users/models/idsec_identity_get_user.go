package models

// IdsecIdentityGetUser represents the schema for finding a user by their username.
type IdsecIdentityGetUser struct {
	UserID   string `json:"user_id,omitempty" mapstructure:"user_id" flag:"user-id" desc:"User ID found by name"`
	Username string `json:"username,omitempty" mapstructure:"username" flag:"username" desc:"User name to find the id for"`
}
