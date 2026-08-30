package models

// IdsecSIATestConnectorReachability represents the schema for testing connector reachability.
//
// A single target can be specified with TargetHostname/TargetPort, or several
// targets can be tested in one request via Targets (which takes precedence). When
// neither a hostname nor a Targets entry is supplied (e.g. a backend-only check),
// no targets are sent to the API.
type IdsecSIATestConnectorReachability struct {
	ConnectorID           string                       `json:"connector_id" mapstructure:"connector_id" flag:"connector-id" desc:"The ID of the connector to test." validate:"required"`
	TargetHostname        string                       `json:"target_hostname" mapstructure:"target_hostname" flag:"target-hostname" desc:"The target hostname used to test the connector."`
	TargetPort            int                          `json:"target_port" mapstructure:"target_port" flag:"target-port" desc:"The target port used to test the connector." default:"22"`
	Targets               []IdsecSIAReachabilityTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"Optional list of {hostname, port} targets to test in a single request. When set, takes precedence over target_hostname/target_port."`
	CheckBackendEndpoints bool                         `json:"check_backend_endpoints" mapstructure:"check_backend_endpoints" flag:"check-backend-endpoints" desc:"Indicates whether to check the backend endpoints."`
}

// IdsecSIAReachabilityTarget is a single {hostname, port} pair to test as part of
// a multi-target reachability request.
type IdsecSIAReachabilityTarget struct {
	Hostname string `json:"hostname" mapstructure:"hostname" flag:"hostname" desc:"The target hostname to test."`
	Port     int    `json:"port" mapstructure:"port" flag:"port" desc:"The target port to test."`
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
