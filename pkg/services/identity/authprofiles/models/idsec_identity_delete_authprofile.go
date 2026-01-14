package models

// IdsecIdentityDeleteAuthProfile represents the schema for deleting an auth profile.
type IdsecIdentityDeleteAuthProfile struct {
	AuthProfileID   string `json:"auth_profile_id,omitempty" mapstructure:"auth_profile_id" flag:"auth-profile-id" desc:"Auth Profile ID to delete"`
	AuthProfileName string `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Auth Profile Name to delete"`
}
