package models

// IdsecSIASettingsRdpTokenMfaCaching represents the RDP token MFA caching configuration for SIA settings.
//
// This model contains configuration options for Multi-Factor Authentication (MFA)
// token caching behavior in Remote Desktop Protocol (RDP) sessions within the Idsec SIA service.
// It includes settings for enabling/disabling token MFA caching, key expiration timing,
// IP enforcement, and token usage limits to control how MFA tokens are cached
// and validated for RDP connections.
type IdsecSIASettingsRdpTokenMfaCaching struct {
	IsMfaCachingEnabled  *bool `json:"is_mfa_caching_enabled,omitempty" mapstructure:"is_mfa_caching_enabled,omitempty" flag:"is-mfa-caching-enabled" desc:"Indicates whether token MFA caching is enabled."`
	KeyExpirationTimeSec *int  `json:"key_expiration_time_sec,omitempty" mapstructure:"key_expiration_time_sec,omitempty" flag:"key-expiration-time-sec" desc:"The expiration time (in seconds) for the token MFA caching key."`
	ClientIPEnforced     *bool `json:"client_ip_enforced,omitempty" mapstructure:"client_ip_enforced,omitempty" flag:"client-ip-enforced" desc:"Indicates whether client IP is enforced for token MFA caching."`
}
