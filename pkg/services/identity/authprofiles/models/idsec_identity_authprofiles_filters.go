package models

// IdsecIdentityAuthProfilesFilters represents the filters for listing identity auth profiles.
type IdsecIdentityAuthProfilesFilters struct {
	AuthProfileName string   `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Filter auth profiles by name"`
	Challenges      []string `json:"challenges,omitempty" mapstructure:"challenges" flag:"challenges" desc:"Filter auth profiles by challenges"`
}
