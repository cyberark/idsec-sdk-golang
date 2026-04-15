// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAGetHTTPSRelay represents the request to retrieve a specific HTTPS relay.
type IdsecSIAGetHTTPSRelay struct {
	ID string `json:"https_relay_id" mapstructure:"https_relay_id" flag:"https-relay-id" desc:"The ID of the HTTPS relay to retrieve."`
}
