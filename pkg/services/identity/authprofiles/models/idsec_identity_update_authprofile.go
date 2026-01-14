package models

// IdsecIdentityUpdateAuthProfile represents the data required to update an identity auth profile.
type IdsecIdentityUpdateAuthProfile struct {
	AuthProfileID     string                 `json:"auth_profile_id" mapstructure:"auth_profile_id" flag:"auth-profile-id" desc:"ID of the auth profile to update" validate:"required"`
	AuthProfileName   string                 `json:"auth_profile_name,omitempty" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Name of the auth profile to update"`
	FirstChallenges   []string               `json:"first_challenges,omitempty" mapstructure:"first_challenges" flag:"first-challenges" desc:"First challenges for the auth profile"`
	SecondChallenges  []string               `json:"second_challenges,omitempty" mapstructure:"second_challenges" flag:"second-challenges" desc:"Second challenges for the auth profile"`
	AdditionalData    map[string]interface{} `json:"additional_data,omitempty" mapstructure:"additional_data" flag:"additional-data" desc:"Additional data for the auth profile"`
	DurationInMinutes int                    `json:"duration_in_minutes,omitempty" mapstructure:"duration_in_minutes" flag:"duration-in-minutes" desc:"Duration in minutes for the auth profile"`
}
