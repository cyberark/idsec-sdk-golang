package models

// IdsecSIASettingsAdbMfaCaching represents the MFA caching configuration for ADB settings.
//
// This model contains configuration options for Multi-Factor Authentication (MFA)
// caching behavior in the Idsec SIA service. It includes settings for enablement status,
// expiration timing, IP enforcement, and token usage limits to control how MFA
// credentials are cached and validated.
type IdsecSIASettingsAdbMfaCaching struct {
	IsMfaCachingEnabled  *bool `json:"is_mfa_caching_enabled,omitempty" mapstructure:"is_mfa_caching_enabled,omitempty" flag:"is-mfa-caching-enabled" desc:"Indicates whether MFA caching is enabled."`
	KeyExpirationTimeSec *int  `json:"key_expiration_time_sec,omitempty" mapstructure:"key_expiration_time_sec,omitempty" flag:"key-expiration-time-sec" desc:"The expiration time (in seconds) for the MFA caching key."`
	ClientIPEnforced     *bool `json:"client_ip_enforced,omitempty" mapstructure:"client_ip_enforced,omitempty" flag:"client-ip-enforced" desc:"Indicates whether client IP is enforced for MFA caching."`
}
