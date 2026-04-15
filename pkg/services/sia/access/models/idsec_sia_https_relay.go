// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAHTTPSRelayStatusCodes represents the numeric status of an HTTPS relay.
// 0 = INACTIVE, 1 = ACTIVE, 2 = INACTIVE+BLOCKED.
type IdsecSIAHTTPSRelayStatusCodes int

const (
	// HTTPSRelayStatusInactive indicates the relay is inactive (0).
	HTTPSRelayStatusInactive IdsecSIAHTTPSRelayStatusCodes = iota
	// HTTPSRelayStatusActive indicates the relay is active (1).
	HTTPSRelayStatusActive
	// HTTPSRelayStatusInactiveBlocked indicates the relay is inactive and blocked (2).
	HTTPSRelayStatusInactiveBlocked
)

// IdsecSIAHTTPSRelay represents an HTTPS relay in the connector management service.
type IdsecSIAHTTPSRelay struct {
	ID                       string                        `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the HTTPS relay." min_length:"2"`
	HostIP                   string                        `json:"host_ip,omitempty" mapstructure:"host_ip,omitempty" flag:"host-ip" desc:"The host machine IP."`
	HostName                 string                        `json:"host_name,omitempty" mapstructure:"host_name,omitempty" flag:"host-name" desc:"The host name."`
	Version                  string                        `json:"version,omitempty" mapstructure:"version,omitempty" flag:"version" desc:"The HTTPS relay version."`
	ActiveSessionsCount      int                           `json:"active_sessions_count" mapstructure:"active_sessions_count" flag:"active-sessions-count" desc:"Number of currently active sessions." ge:"0"`
	StatusCode               IdsecSIAHTTPSRelayStatusCodes `json:"status_code" mapstructure:"status_code" flag:"status-code" desc:"Numeric status: 0=INACTIVE, 1=ACTIVE, 2=INACTIVE+BLOCKED."`
	Status                   string                        `json:"status,omitempty" mapstructure:"status,omitempty" flag:"status" desc:"Human-readable status." default:"INACTIVE"`
	OS                       string                        `json:"os,omitempty" mapstructure:"os,omitempty" flag:"os" desc:"Operating system of the relay host."`
	ProxySettings            string                        `json:"proxy_settings,omitempty" mapstructure:"proxy_settings,omitempty" flag:"proxy-settings" desc:"HTTP proxy details if configured."`
	IsLatestVersion          bool                          `json:"is_latest_version" mapstructure:"is_latest_version" flag:"is-latest-version" desc:"Whether the relay is on the latest version." default:"true"`
	VersionToUpgrade         string                        `json:"version_to_upgrade,omitempty" mapstructure:"version_to_upgrade,omitempty" flag:"version-to-upgrade" desc:"Version to upgrade to, if not on latest."`
	IsUpgradable             bool                          `json:"is_upgradable" mapstructure:"is_upgradable" flag:"is-upgradable" desc:"Whether the relay can be upgraded."`
	LastJobStatus            string                        `json:"last_job_status,omitempty" mapstructure:"last_job_status,omitempty" flag:"last-job-status" desc:"Status of the last executed job."`
	LastJobErrorCode         string                        `json:"last_job_error_code,omitempty" mapstructure:"last_job_error_code,omitempty" flag:"last-job-error-code" desc:"Error code of the last executed job."`
	LastJobStatusDescription string                        `json:"last_job_status_description,omitempty" mapstructure:"last_job_status_description,omitempty" flag:"last-job-status-description" desc:"Description of the last executed job."`
	LastJobInfoUpdateDate    string                        `json:"last_job_info_update_date,omitempty" mapstructure:"last_job_info_update_date,omitempty" flag:"last-job-info-update-date" desc:"Timestamp of the last job status update."`
}
