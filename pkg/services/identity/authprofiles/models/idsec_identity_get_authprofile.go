package models

// IdsecIdentityGetAuthProfile represents the schema for retrieving an auth profile.
type IdsecIdentityGetAuthProfile struct {
	AuthProfileID   string `json:"auth_profile_id,omitempty" mapstructure:"auth_profile_id" flag:"auth-profile-id" desc:"Auth Profile ID to retrieve"`
	AuthProfileName string `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Auth Profile Name to retrieve"`
}
