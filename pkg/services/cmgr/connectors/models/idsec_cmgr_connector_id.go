package models

// IdsecCmgrConnectorID represents the result of a successful connector installation.
type IdsecCmgrConnectorID struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID of the installed management agent connector." validate:"required"`
}
