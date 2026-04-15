// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIADeleteHTTPSRelay represents the request to delete a specific HTTPS relay.
type IdsecSIADeleteHTTPSRelay struct {
	ID string `json:"https_relay_id" mapstructure:"id" flag:"https-relay-id" desc:"The ID of the HTTPS relay to delete."`
}
