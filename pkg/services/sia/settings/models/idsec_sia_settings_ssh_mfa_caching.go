package models

// IdsecSIASettingsSshMfaCaching represents the SSH MFA caching configuration for SIA settings.
//
// This model contains configuration options for Multi-Factor Authentication (MFA)
// caching behavior in SSH connections within the Idsec SIA service. It includes
// settings for enabling/disabling MFA caching and configuring the expiration
// time for cached MFA tokens to balance security and user experience.
type IdsecSIASettingsSshMfaCaching struct {
	IsMfaCachingEnabled  *bool `json:"is_mfa_caching_enabled,omitempty" mapstructure:"is_mfa_caching_enabled,omitempty" flag:"is-mfa-caching-enabled" desc:"Indicates whether MFA caching is enabled."`
	KeyExpirationTimeSec *int  `json:"key_expiration_time_sec,omitempty" mapstructure:"key_expiration_time_sec,omitempty" flag:"key-expiration-time-sec" desc:"The expiration time (in seconds) for the MFA caching key."`
	ClientIPEnforced     *bool `json:"client_ip_enforced,omitempty" mapstructure:"client_ip_enforced,omitempty" flag:"client-ip-enforced" desc:"Indicates whether client IP is enforced for MFA caching."`
}
