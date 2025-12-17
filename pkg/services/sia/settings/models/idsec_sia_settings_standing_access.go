package models

// IdsecSIASettingsStandingAccess represents the standing access configuration for SIA settings.
//
// This model contains configuration options for standing access capabilities
// in the Idsec SIA service. It defines availability settings for different protocol
// types (SSH, RDP, ADB), session management parameters including maximum duration
// and idle timeouts, and security features like fingerprint validation to control
// how standing access sessions are managed and secured across various connection types.
type IdsecSIASettingsStandingAccess struct {
	StandingAccessAvailable    *bool `json:"standing_access_available,omitempty" mapstructure:"standing_access_available,omitempty" flag:"standing-access-available" desc:"Whether standing access is available"`
	SessionMaxDuration         *int  `json:"session_max_duration,omitempty" mapstructure:"session_max_duration,omitempty" flag:"session-max-duration" desc:"Maximum duration of a session"`
	SessionIdleTime            *int  `json:"session_idle_time,omitempty" mapstructure:"session_idle_time,omitempty" flag:"session-idle-time" desc:"Idle time before a session is considered inactive"`
	FingerprintValidation      *bool `json:"fingerprint_validation,omitempty" mapstructure:"fingerprint_validation,omitempty" flag:"fingerprint-validation" desc:"Whether fingerprint validation is enabled"`
	SSHStandingAccessAvailable *bool `json:"ssh_standing_access_available,omitempty" mapstructure:"ssh_standing_access_available,omitempty" flag:"ssh-standing-access-available" desc:"Whether SSH standing access is available"`
	RDPStandingAccessAvailable *bool `json:"rdp_standing_access_available,omitempty" mapstructure:"rdp_standing_access_available,omitempty" flag:"rdp-standing-access-available" desc:"Whether RDP standing access is available"`
	ADBStandingAccessAvailable *bool `json:"adb_standing_access_available,omitempty" mapstructure:"adb_standing_access_available,omitempty" flag:"adb-standing-access-available" desc:"Whether ADB standing access is available"`
}
