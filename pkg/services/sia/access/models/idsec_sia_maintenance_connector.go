package models

// IdsecSIAMaintenanceConnector represents the request to put a connector into maintenance mode in Idsec SIA.
type IdsecSIAMaintenanceConnector struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The connector ID to put into maintenance mode" validate:"required"`
	Maintenance bool   `json:"maintenance" mapstructure:"maintenance" flag:"maintenance" desc:"Set to true to enable maintenance mode (--maintenance), false to disable (--maintenance=false)" default:"false"`
	RetryCount  int    `json:"retry_count" mapstructure:"retry_count" flag:"retry-count" desc:"Number of times to retry putting the connector into maintenance mode if it fails" default:"10"`
	RetryDelay  int    `json:"retry_delay" mapstructure:"retry_delay" flag:"retry-delay" desc:"Delay in seconds between retries" default:"5"`
}

type IdsecSIAMaintenanceConnectorStatus struct {
	ConnectorID string `json:"connector_id" mapstructure:"connector_id"`
	Maintenance bool   `json:"maintenance" mapstructure:"maintenance"`
}
