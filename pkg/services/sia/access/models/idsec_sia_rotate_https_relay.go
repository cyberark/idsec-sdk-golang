// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIARotateHTTPSRelay represents the request to rotate certificates for a specific HTTPS relay.
type IdsecSIARotateHTTPSRelay struct {
	HTTPSRelayID string `json:"https_relay_id" mapstructure:"https_relay_id" flag:"https-relay-id" desc:"The ID of the HTTPS relay to rotate certificates for."`
}
