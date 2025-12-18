package models

// IdsecSIATestConnectorReachability represents the schema for testing connector reachability.
type IdsecSIATestConnectorReachability struct {
	ConnectorID           string `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector to test." validate:"required"`
	TargetHostname        string `json:"target_hostname" mapstructure:"target_hostname" flag:"target-hostname" desc:"The target hostname used to test the connector."`
	TargetPort            int    `json:"target_port" mapstructure:"target_port" flag:"target-port" desc:"The target port used to test the connector." default:"22"`
	CheckBackendEndpoints bool   `json:"check_backend_endpoints" mapstructure:"check_backend_endpoints" flag:"check-backend-endpoints" desc:"Indicates whether to check the backend endpoints."`
}

// IdsecSIATargetElement represents the schema for a target element in the reachability test response.
type IdsecSIATargetElement struct {
	TargetIP     string `json:"target_ip" mapstructure:"target_ip"`
	TargetPort   int    `json:"target_port" mapstructure:"target_port"`
	LatencyMlsec int    `json:"latency_mlsec" mapstructure:"latency_mlsec"`
	Status       string `json:"status" mapstructure:"status"`
	Description  string `json:"description" mapstructure:"description"`
}

// IdsecSIABackendEndpoint represents the schema for a backend endpoint in the reachability test response.
type IdsecSIABackendEndpoint struct {
	BackendConnectorAddress string `json:"backend_connector_endpoint" mapstructure:"backend_connector_endpoint"`
	LatencyMlsec            int    `json:"latency_mlsec" mapstructure:"latency_mlsec"`
	Status                  string `json:"status" mapstructure:"status"`
	Description             string `json:"description" mapstructure:"description"`
}

// IdsecSIAReachabilityTestResponse represents the response for the reachability test.
type IdsecSIAReachabilityTestResponse struct {
	Targets  []IdsecSIATargetElement   `json:"targets" mapstructure:"targets"`
	Backends []IdsecSIABackendEndpoint `json:"backends" mapstructure:"backends"`
}
