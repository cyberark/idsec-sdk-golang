package models

// IdsecCmgrGet represents the request parameters for retrieving a specific connector.
type IdsecCmgrGet struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector to get." required:"true"`
}
