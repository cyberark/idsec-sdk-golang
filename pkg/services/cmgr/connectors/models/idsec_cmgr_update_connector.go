package models

// IdsecCmgrUpdate represents the request parameters for updating a specific connector.
type IdsecCmgrUpdate struct {
	ConnectorID     string  `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector to update." required:"true"`
	ConnectorPoolID *string `json:"connector_pool_id" mapstructure:"connector_pool_id" flag:"connector-pool-id" desc:"The connector pool ID to assign the connector to." required:"true"`
}
