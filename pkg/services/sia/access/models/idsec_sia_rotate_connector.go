// Package models provides request and response model types for the SIA access service.
package models

// IdsecSIARotateConnector represents the request to rotate certificates for a specific connector.
type IdsecSIARotateConnector struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector to rotate certificates for."`
}
