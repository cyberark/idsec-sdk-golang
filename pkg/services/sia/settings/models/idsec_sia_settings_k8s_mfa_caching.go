package models

// IdsecSIASettingsK8sMfaCaching represents the MFA caching configuration for K8S settings.
//
// This model contains configuration options for Multi-Factor Authentication (MFA)
// caching behavior in Kubernetes environments within the Idsec SIA service. It includes
// settings for key expiration timing, IP enforcement, and token usage limits to control
// how MFA credentials are cached and validated for K8S access.
type IdsecSIASettingsK8sMfaCaching struct {
	KeyExpirationTimeSec *int  `json:"key_expiration_time_sec,omitempty" mapstructure:"key_expiration_time_sec,omitempty" flag:"key-expiration-time-sec" desc:"Expiration time for the MFA caching key in seconds" default:"7200"`
	ClientIPEnforced     *bool `json:"client_ip_enforced,omitempty" mapstructure:"client_ip_enforced,omitempty" flag:"client-ip-enforced" desc:"Whether client IP is enforced for MFA caching" default:"true"`
}
