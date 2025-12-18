package models

// IdsecSIADeleteConnector represents the request to delete a connector in Idsec SIA.
type IdsecSIADeleteConnector struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID of the connector to delete." validate:"required"`
	RetryCount  int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry to delete the connector, if it fails." default:"10"`
	RetryDelay  int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
}
