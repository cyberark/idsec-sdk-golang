package models

// IdsecIdentityUserByName represents the schema for finding a user by their username.
type IdsecIdentityUserByName struct {
	Username string `json:"username" mapstructure:"username" flag:"username" desc:"User name to find the id for" required:"true"`
}
