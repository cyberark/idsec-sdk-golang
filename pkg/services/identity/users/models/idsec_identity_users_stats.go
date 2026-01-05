package models

// IdsecIdentityUsersStats represents statistics about users in the identity service.
type IdsecIdentityUsersStats struct {
	UsersCount int `json:"users_count" mapstructure:"users_count" flag:"users-count" desc:"Total number of users in the identity service"`
}
