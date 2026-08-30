package models

// IdsecSIADoctorCheckConnector is the input for the connector-mode check.
// It verifies that each connector can reach its backend, and optionally also
// reach one or more target machines. Backend and target reachability are
// measured via the SIA reachability API (which probes from the connector's
// side); credentials, when supplied on a connector machine, are used only to
// read that machine's connector ID from its local config.
//
// Connectors can be supplied three ways:
//   - ConnectorIDs: explicit connector IDs, used directly.
//   - ConnectorMachines: machines to SSH/WinRM into to read their connector ID.
//   - Local: read the connector ID from the local config file on this machine.
//
// When none of the above is supplied the default is to check EVERY connector in
// the tenant.
//
// Example JSON:
//
//	{
//	  "local": false,
//	  "connector_ids": ["conn-abc123"],
//	  "connector_machines": [
//	    { "hostname": "connector1", "os_type": "linux",
//	      "username": "ec2-user", "private_key_path": "/home/me/id_rsa" }
//	  ],
//	  "targets": [ { "hostname": "db.example.com" } ]
//	}
//
// All fields are optional; an empty body checks every connector in the tenant.
type IdsecSIADoctorCheckConnector struct {
	// Local restricts the check to the connector installed on the machine running
	// the SDK (its ID is read from the local connector config file). When false
	// (default) and no explicit ConnectorIDs / ConnectorMachines are given, every
	// connector in the tenant is checked. Only Active connectors are
	// reachability-tested; non-active ones are reported as skipped with their
	// status rather than firing a reachability call that would just fail.
	Local bool `json:"local" mapstructure:"local" flag:"local" default:"false" desc:"Check only the local connector (read from the local connector config). Default (false) checks every connector in the tenant."`

	// ConnectorIDs lists explicit connector IDs to check.
	ConnectorIDs []string `json:"connector_ids" mapstructure:"connector_ids" flag:"connector-ids" desc:"Explicit connector IDs to check. Example: [\"conn-abc123\",\"conn-def456\"]"`

	// ConnectorMachines lists connector machines to SSH/WinRM into and read the
	// connector ID from the local connector config. Each entry is a target that
	// may carry direct-connection credentials and its own OSType.
	ConnectorMachines []IdsecSIADoctorTarget `json:"connector_machines" mapstructure:"connector_machines" flag:"connector-machines" desc:"Array of connector-machine objects to read connector IDs from via SSH/WinRM. Per-object keys: hostname (required), os_type (linux|darwin|windows), username, password, private_key_path, winrm_protocol. Example: [{\"hostname\":\"connector1\",\"os_type\":\"linux\",\"username\":\"ec2-user\",\"private_key_path\":\"/home/me/id_rsa\"}]"`

	// Targets lists optional target machines for connector→target reachability checks.
	// The same flow×protocol matrix as target mode is applied for each target.
	Targets []IdsecSIADoctorTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"Optional array of target objects for connector→target reachability (same object shape as target mode). Example: [{\"hostname\":\"db.example.com\"}]"`

	// ConcurrencyLimit caps how many per-connector tasks run simultaneously.
	// Defaults to 32 when zero.
	ConcurrencyLimit int `json:"concurrency_limit" mapstructure:"concurrency_limit" flag:"concurrency-limit" default:"32" desc:"Max parallel connector checks (default 32)."`

	// TimeoutSec is the wall-clock limit in seconds for the entire operation.
	// Defaults to 30 s when zero.
	TimeoutSec int `json:"timeout_sec" mapstructure:"timeout_sec" flag:"timeout-sec" default:"30" desc:"Overall operation timeout in seconds (default 30)."`

	// BatchReachability selects the alternative reachability path: instead of one
	// TestConnectorReachability API call per (host, port), a single call per host
	// carries all of that host's ports as a multi-target request. Experimental —
	// used to compare throughput against the default per-port-parallel path.
	BatchReachability bool `json:"batch_reachability" mapstructure:"batch_reachability" flag:"batch-reachability" default:"true" desc:"Send all of a target's ports in one reachability API call instead of one call per port (default true)."`
}
