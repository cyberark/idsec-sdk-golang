package models

// IdsecSIAAccessConnectorID is a struct that represents the connector ID for Idsec SIA Access.
type IdsecSIAAccessConnectorID struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID" validate:"required"`
}
