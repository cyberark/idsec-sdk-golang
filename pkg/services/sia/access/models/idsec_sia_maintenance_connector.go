package models

// IdsecSIAMaintenanceConnector represents the request to put a connector into maintenance mode in Idsec SIA.
type IdsecSIAMaintenanceConnector struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID of the connector to set to maintenance mode." validate:"required"`
	Maintenance bool   `json:"maintenance" mapstructure:"maintenance" flag:"maintenance" desc:"Set to true to enable maintenance mode (--maintenance) or set to false to disable maintenance mode (--maintenance=false)." default:"false"`
	RetryCount  int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"The number of times to retry setting the connector to maintenance mode, if it fails." default:"10"`
	RetryDelay  int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"The number of seconds to wait between retries." default:"5"`
}

type IdsecSIAMaintenanceConnectorStatus struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id"`
	Maintenance bool   `json:"maintenance" mapstructure:"maintenance"`
}
