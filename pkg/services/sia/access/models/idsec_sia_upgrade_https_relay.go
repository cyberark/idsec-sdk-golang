// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIAUpgradeHTTPSRelay represents the request to upgrade a specific HTTPS relay.
type IdsecSIAUpgradeHTTPSRelay struct {
	ID string `json:"https_relay_id" mapstructure:"https_relay_id" flag:"https-relay-id" desc:"The ID of the HTTPS relay to upgrade."`
}
