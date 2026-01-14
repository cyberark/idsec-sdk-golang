package models

// IdsecIdentityAuthProfilesStats represents statistics related to identity auth profiles.
type IdsecIdentityAuthProfilesStats struct {
	AuthProfilesCount int `json:"auth_profiles_count" mapstructure:"auth_profiles_count" desc:"Total number of auth profiles"`
}
