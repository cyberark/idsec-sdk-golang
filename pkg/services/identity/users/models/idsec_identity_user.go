package models

import "time"

// IdsecIdentityUser represents the schema for a user.
type IdsecIdentityUser struct {
	UserID          string            `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"User identifier"`
	Username        string            `json:"username" mapstructure:"username" flag:"username" desc:"Name of the user"`
	Password        *string           `json:"password,omitempty" mapstructure:"password" flag:"password" desc:"Password of the user"`
	DisplayName     string            `json:"display_name,omitempty" mapstructure:"display_name" flag:"display-name" desc:"Display name of the user"`
	Email           string            `json:"email,omitempty" mapstructure:"email" flag:"email" desc:"Email of the user"`
	MobileNumber    string            `json:"mobile_number,omitempty" mapstructure:"mobile_number" flag:"mobile-number" desc:"Mobile number of the user"`
	Suffix          string            `json:"suffix,omitempty" mapstructure:"suffix" flag:"suffix" desc:"Suffix of the user"`
	InEverybodyRole *bool             `json:"in_everybody_role,omitempty" mapstructure:"in_everybody_role" flag:"in-everybody-role" desc:"Whether to add the user to the 'Everybody' role"`
	LastLogin       *time.Time        `json:"last_login,omitempty" mapstructure:"last_login" flag:"last-login" desc:"Last login time of the user"`
	IsServiceUser   *bool             `json:"is_service_user" mapstructure:"is_service_user" flag:"is-service-user" desc:"Whether the user is a service user"`
	IsOauthClient   *bool             `json:"is_oauth_client" mapstructure:"is_oauth_client" flag:"is-oauth-client" desc:"Whether the user is an OAuth client"`
	State           string            `json:"state,omitempty" mapstructure:"state" flag:"state" desc:"State of the user, can be None, Locked, Disabled, or Expired" choices:"None,Locked,Disabled,Expired"`
	UserAttributes  map[string]string `json:"user_attributes,omitempty" mapstructure:"user_attributes" flag:"user-attributes" desc:"Custom attributes of the user"`
}
