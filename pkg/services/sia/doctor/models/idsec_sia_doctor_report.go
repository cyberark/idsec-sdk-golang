package models

// IdsecSIADoctorReport is the result returned by every Check* method.
type IdsecSIADoctorReport struct {
	Mode    string                      `json:"mode" mapstructure:"mode"`
	Checks  []IdsecSIADoctorCheckResult `json:"checks" mapstructure:"checks"`
	Summary IdsecSIADoctorSummary       `json:"summary" mapstructure:"summary"`
	// UnreachableTargets lists target hostnames / addresses for which no
	// protocol check passed.  Computed before N/A filtering so it reflects
	// every target that could not be confirmed reachable.
	UnreachableTargets []string `json:"unreachable_targets,omitempty" mapstructure:"unreachable_targets"`
	// Connectors carries descriptive metadata for the connectors referenced by
	// connector-mode reports, keyed by ID, so the output can identify which
	// connector (host / IP / platform) needs attention.
	Connectors []IdsecSIADoctorConnectorInfo `json:"connectors,omitempty" mapstructure:"connectors"`
	// DurationMs is the overall wall-clock time, in milliseconds, the Check*
	// operation took to evaluate (from entry to the assembled report).
	DurationMs int64 `json:"duration_ms" mapstructure:"duration_ms"`
}

// IdsecSIADoctorConnectorInfo is descriptive metadata about a connector, shown
// in the connector-mode report header so a customer can tell which physical
// connector a section refers to.
type IdsecSIADoctorConnectorInfo struct {
	ID       string `json:"id" mapstructure:"id"`
	HostName string `json:"host_name,omitempty" mapstructure:"host_name"`
	HostIP   string `json:"host_ip,omitempty" mapstructure:"host_ip"`
	HostType string `json:"host_type,omitempty" mapstructure:"host_type"`
	OS       string `json:"os,omitempty" mapstructure:"os"`
	Version  string `json:"version,omitempty" mapstructure:"version"`
	Status   string `json:"status,omitempty" mapstructure:"status"`
	Region   string `json:"region,omitempty" mapstructure:"region"`
}

// IdsecSIADoctorCheckResult holds the outcome of a single reachability or configuration check.
type IdsecSIADoctorCheckResult struct {
	// Mode is the doctor mode that produced this row: "client", "target",
	// "connector", or "domain-controller". Populated only by the unified "check"
	// command so its report can be banded by mode; empty for single-mode reports.
	Mode string `json:"mode,omitempty" mapstructure:"mode"`
	// Protocol identifies the access protocol being tested, e.g. "rdp", "ssh", "mysql",
	// "ldap", "kerberos", "ssh-ca-key".
	Protocol string `json:"protocol" mapstructure:"protocol"`
	// Flow identifies the SIA access flow this check belongs to.
	// One of: "vaulted", "zsp-local-ephemeral", "zsp-domain-ephemeral",
	// "jit-elevation", "zsp-ssh-certs", "gw", "relay", "backend", "dc".
	Flow string `json:"flow" mapstructure:"flow"`
	// Host is the hostname or IP that was tested.
	Host string `json:"host" mapstructure:"host"`
	// Port is the TCP port that was tested (0 when not applicable, e.g. backend check).
	Port int `json:"port" mapstructure:"port"`
	// Status is "pass", "fail", "n/a" (protocol not running on target), or
	// "skipped" (required credentials were not provided).
	Status string `json:"status" mapstructure:"status"`
	// LatencyMs is the round-trip latency in milliseconds.
	// Populated from the SIA API reachability response, or measured locally for client-mode checks.
	LatencyMs int `json:"latency_ms" mapstructure:"latency_ms"`
	// Description is a human-readable detail message.
	Description string `json:"description" mapstructure:"description"`
	// CheckedFrom indicates who performed the check.
	// "local" for client-mode checks; "connector:{connectorID}" for API-based checks.
	CheckedFrom string `json:"checked_from" mapstructure:"checked_from"`
	// Warning carries a non-fatal advisory attached to this check, e.g. the
	// server's TLS certificate for this protocol does not chain to any tenant
	// certificate. Empty when there is nothing to warn about.
	Warning string `json:"warning,omitempty" mapstructure:"warning"`
	// CertStatus is the TLS certificate validation verdict for this protocol row.
	// One of CertStatusTrusted, CertStatusUntrusted, CertStatusUnverified, or
	// empty when no certificate check applies (e.g. SSH, or the port was not
	// reachable to probe).
	CertStatus string `json:"cert_status,omitempty" mapstructure:"cert_status"`
}

// IdsecSIADoctorSummary aggregates the check counts from a report.
type IdsecSIADoctorSummary struct {
	Total    int `json:"total" mapstructure:"total"`
	Passed   int `json:"passed" mapstructure:"passed"`
	Failed   int `json:"failed" mapstructure:"failed"`
	NA       int `json:"na" mapstructure:"na"`
	Skipped  int `json:"skipped" mapstructure:"skipped"`
	Warnings int `json:"warnings" mapstructure:"warnings"`
}

const (
	// CheckStatusPass indicates the check succeeded.
	CheckStatusPass = "pass"
	// CheckStatusFail indicates the check failed.
	CheckStatusFail = "fail"
	// CheckStatusNA indicates the protocol is not running on this target
	// (base port unreachable, or all associated base protocols are N/A).
	// N/A results are hidden by default; pass ShowAll=true to include them.
	CheckStatusNA = "n/a"
	// CheckStatusSkipped indicates the check was skipped due to missing credentials.
	CheckStatusSkipped = "skipped"

	// CertStatusTrusted indicates the server TLS certificate chains to a tenant certificate.
	CertStatusTrusted = "trusted"
	// CertStatusUntrusted indicates the server TLS certificate does not chain to any tenant certificate.
	CertStatusUntrusted = "untrusted"
	// CertStatusUnverified indicates the certificate trust could not be determined
	// (e.g. the tenant certificate list could not be fetched).
	CertStatusUnverified = "unverified"

	// Flow constants.
	FlowVaulted            = "vaulted"
	FlowZSPLocalEphemeral  = "zsp-local-ephemeral"
	FlowZSPDomainEphemeral = "zsp-domain-ephemeral"
	FlowJITElevation       = "jit-elevation"
	FlowZSPSSHCerts        = "zsp-ssh-certs"
	FlowGW                 = "gw"
	FlowRelay              = "relay"
	FlowBackend            = "backend"
	FlowDC                 = "dc"
	// FlowTLSCertificate groups per-protocol server-certificate → tenant-trust-chain checks.
	FlowTLSCertificate = "tls-certificate"
)
