package models

// IdsecCmgrConnector represents a connector returned by the connector management service.
type IdsecCmgrConnector struct {
	ConnectorID     string   `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector."`
	ConnectorStatus string   `json:"connector_status" mapstructure:"connector_status" flag:"connector-status" desc:"The status of the connector."`
	PlatformType    string   `json:"platform_type" mapstructure:"platform_type" flag:"platform-type" desc:"The host platform type."`
	ConnectorPoolID string   `json:"connector_pool_id,omitempty" mapstructure:"connector_pool_id,omitempty" flag:"connector-pool-id" desc:"The connector pool ID."`
	Version         string   `json:"version" mapstructure:"version" flag:"version" desc:"The version of the connector."`
	UpgradeVersions []string `json:"upgrade_versions" mapstructure:"upgrade_versions" flag:"upgrade-versions" desc:"Available upgrade versions."`
	InstalledAt     int64    `json:"installed_at" mapstructure:"installed_at" flag:"installed-at" desc:"The installation time of the connector (epoch timestamp)."`
	UpdatedAt       int64    `json:"updated_at" mapstructure:"updated_at" flag:"updated-at" desc:"The last update time of the connector (epoch timestamp)."`
}
