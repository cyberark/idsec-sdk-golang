package models

// IdsecSIASettingsValidateFingerprintForSSHZeroStanding represents the SSH fingerprint validation
// configuration for Zero Standing connections.
//
// This setting controls whether SSH fingerprint validation is enabled when connecting
// to targets via Zero Standing access. When enabled, SSH host key fingerprints must be
// validated before establishing connections.
type IdsecSIASettingsValidateFingerprintForSSHZeroStanding struct {
	Enabled *bool `json:"enabled,omitempty" mapstructure:"enabled,omitempty" flag:"enabled" desc:"Whether SSH fingerprint validation is enabled for Zero Standing connections"`
}
