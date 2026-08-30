package models

// IdsecSIADoctorCheck is the input for the unified "check" command, which runs
// several doctor modes in a single pass and returns one merged report.
//
// Mode selection:
//   - Client and connector modes always run (they need no input: client checks
//     the local machine, connector checks every tenant connector).
//   - Target mode runs when "targets" is provided.
//   - Domain-controller mode runs when "domain_controllers" is provided.
//   - "modes" overrides the above: set it to run exactly the listed subset
//     (accepted values: client, target, connector, domain-controller; "dc" is
//     accepted as an alias for domain-controller).
//
// Shared inputs (protocols, connector_ids, credentials-carrying machine lists,
// concurrency_limit, timeout_sec, disable_certificate_check) fan out to every
// mode that consumes them, so the four modes stay configured consistently.
//
// Example JSON (full sweep):
//
//	{
//	  "modes": ["client","connector","target","domain-controller"],
//	  "clients":            [ { "hostname": "client1", "os_type": "linux", "username": "ec2-user", "private_key_path": "/home/me/id_rsa" } ],
//	  "targets":            [ { "hostname": "db.example.com" } ],
//	  "domain_controllers": [ { "hostname": "dc1.corp.local", "os_type": "windows", "username": "admin", "password": "secret" } ],
//	  "timeout_sec": 120
//	}
//
// An empty body runs the local client check plus every tenant connector.
type IdsecSIADoctorCheck struct {
	// Modes selects which modes to run. Empty = auto: client + connector always,
	// plus target / domain-controller when their machine lists are provided.
	Modes []string `json:"modes" mapstructure:"modes" flag:"modes" desc:"Subset of modes to run: client|target|connector|domain-controller (dc alias accepted). Empty = auto-detect (client + connector always; target/dc when their inputs are given)."`

	// Clients lists the machines to run the client gateway/relay checks from.
	// Empty = the local machine. Same object shape as target mode.
	Clients []IdsecSIADoctorTarget `json:"clients" mapstructure:"clients" flag:"clients" desc:"Client machines to run gateway/relay reachability from (same object shape as targets). Empty = local machine."`

	// Targets lists the machines checked in target mode (connector→target
	// reachability across every flow/protocol). Providing it enables target mode.
	Targets []IdsecSIADoctorTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"Target machines for connector→target reachability. Per-object keys: hostname (required), os_type, username, password, private_key_path, winrm_protocol, <proto>_port overrides. Providing this enables target mode."`

	// DomainControllers lists the DCs checked in domain-controller mode.
	// Providing it enables domain-controller mode.
	DomainControllers []IdsecSIADoctorTarget `json:"domain_controllers" mapstructure:"domain_controllers" flag:"domain-controllers" desc:"Domain controllers for connector→DC reachability + LDAPS/RDP cert checks (same object shape as targets). Providing this enables domain-controller mode."`

	// ConnectorIDs is the shared connector filter. In target / domain-controller
	// mode it restricts which connectors run the reachability checks; in
	// connector mode it is the explicit set of connectors to check. Empty = all
	// connectors.
	ConnectorIDs []string `json:"connector_ids" mapstructure:"connector_ids" flag:"connector-ids" desc:"Connector IDs to use (target/DC: connectors that test; connector mode: connectors to check). Empty = all connectors."`

	// LocalConnector restricts connector mode to the connector installed on the
	// local machine (read from its config). Default (false) checks every tenant
	// connector, matching standalone check-connector.
	LocalConnector bool `json:"local_connector" mapstructure:"local_connector" flag:"local-connector" default:"false" desc:"Connector mode: check only the local connector. Default (false) checks every tenant connector."`

	// Protocols is the shared protocol filter for client and target modes.
	// Empty = all protocols.
	Protocols []string `json:"protocols" mapstructure:"protocols" flag:"protocols" desc:"Protocol filter for client and target modes. Empty = all."`

	// ShowAll includes N/A results from target mode in the report.
	ShowAll bool `json:"show_all" mapstructure:"show_all" flag:"show-all" desc:"Include N/A (not-applicable) target results in output (default false)."`

	// ConnectTimeout is the client-mode TCP dial timeout in seconds (default 5).
	ConnectTimeout int `json:"connect_timeout" mapstructure:"connect_timeout" flag:"connect-timeout" default:"5" desc:"Client-mode TCP dial timeout in seconds (default 5)."`

	// DisableCertificateCheck turns off TLS certificate validation across every
	// mode (client OS-trust probing, target/DC tenant-trust probing).
	DisableCertificateCheck bool `json:"disable_certificate_check" mapstructure:"disable_certificate_check" flag:"disable-certificate-check" default:"false" desc:"Disable TLS certificate validation across all modes."`

	// ConcurrencyLimit caps parallel work within each mode. Defaults to 32.
	ConcurrencyLimit int `json:"concurrency_limit" mapstructure:"concurrency_limit" flag:"concurrency-limit" default:"32" desc:"Max parallel checks within each mode (default 32)."`

	// TimeoutSec is the per-mode wall-clock limit in seconds, applied to target,
	// domain-controller, and connector modes. Defaults to each mode's own default
	// when zero.
	TimeoutSec int `json:"timeout_sec" mapstructure:"timeout_sec" flag:"timeout-sec" desc:"Per-mode operation timeout in seconds (applies to target/DC/connector modes)."`

	// BatchReachability selects the experimental batched reachability path for
	// target and connector modes.
	BatchReachability bool `json:"batch_reachability" mapstructure:"batch_reachability" flag:"batch-reachability" default:"true" desc:"Send all of a host's ports in one reachability API call instead of one per port — target/connector modes (default true)."`
}

// ClientRequest projects the unified request onto a client-mode request.
func (r *IdsecSIADoctorCheck) ClientRequest() *IdsecSIADoctorCheckClient {
	return &IdsecSIADoctorCheckClient{
		Clients:                 r.Clients,
		Protocols:               r.Protocols,
		ConnectTimeout:          r.ConnectTimeout,
		DisableCertificateCheck: r.DisableCertificateCheck,
	}
}

// TargetRequest projects the unified request onto a target-mode request.
func (r *IdsecSIADoctorCheck) TargetRequest() *IdsecSIADoctorCheckTarget {
	return &IdsecSIADoctorCheckTarget{
		Targets:                 r.Targets,
		Protocols:               r.Protocols,
		ConnectorIDs:            r.ConnectorIDs,
		ShowAll:                 r.ShowAll,
		ConcurrencyLimit:        r.ConcurrencyLimit,
		TimeoutSec:              r.TimeoutSec,
		DisableCertificateCheck: r.DisableCertificateCheck,
		BatchReachability:       r.BatchReachability,
	}
}

// DomainControllerRequest projects the unified request onto a DC-mode request.
func (r *IdsecSIADoctorCheck) DomainControllerRequest() *IdsecSIADoctorCheckDomainController {
	return &IdsecSIADoctorCheckDomainController{
		DomainControllers:       r.DomainControllers,
		ConnectorIDs:            r.ConnectorIDs,
		DisableCertificateCheck: r.DisableCertificateCheck,
		ConcurrencyLimit:        r.ConcurrencyLimit,
		TimeoutSec:              r.TimeoutSec,
	}
}

// ConnectorRequest projects the unified request onto a connector-mode request.
// Target reachability is intentionally left to target mode, so connector mode
// here focuses on backend reachability.
func (r *IdsecSIADoctorCheck) ConnectorRequest() *IdsecSIADoctorCheckConnector {
	return &IdsecSIADoctorCheckConnector{
		Local:             r.LocalConnector,
		ConnectorIDs:      r.ConnectorIDs,
		ConcurrencyLimit:  r.ConcurrencyLimit,
		TimeoutSec:        r.TimeoutSec,
		BatchReachability: r.BatchReachability,
	}
}
