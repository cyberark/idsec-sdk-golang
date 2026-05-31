// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIADeleteHTTPSRelay represents the request to delete a specific HTTPS relay.
type IdsecSIADeleteHTTPSRelay struct {
	HTTPSRelayID string `json:"https_relay_id" mapstructure:"https_relay_id" flag:"https-relay-id" desc:"The ID of the HTTPS relay to delete."`
	ForceDelete  bool   `json:"force_delete" mapstructure:"force_delete" flag:"force-delete" desc:"When true, forces deletion of the HTTPS relay even if it has active sessions." default:"false"`
	RetryCount   int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry the deletion API, if it fails." default:"10"`
	RetryDelay   int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
}
