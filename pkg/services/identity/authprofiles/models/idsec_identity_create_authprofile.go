package models

// IdsecIdentityCreateAuthProfile represents the data required to create an identity auth profile.
type IdsecIdentityCreateAuthProfile struct {
	AuthProfileName   string                 `json:"auth_profile_name" mapstructure:"auth_profile_name" flag:"auth-profile-name" desc:"Name of the auth profile to create" validate:"required"`
	FirstChallenges   []string               `json:"first_challenges" mapstructure:"first_challenges" flag:"first-challenges" desc:"First challenges for the auth profile" validate:"required"`
	SecondChallenges  []string               `json:"second_challenges,omitempty" mapstructure:"second_challenges" flag:"second-challenges" desc:"Second challenges for the auth profile"`
	AdditionalData    map[string]interface{} `json:"additional_data,omitempty" mapstructure:"additional_data" flag:"additional-data" desc:"Additional data for the auth profile"`
	DurationInMinutes int                    `json:"duration_in_minutes,omitempty" mapstructure:"duration_in_minutes" flag:"duration-in-minutes" desc:"Duration in minutes for the auth profile" default:"30"`
}
