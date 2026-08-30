package models

// IdsecSIADoctorCheckDomainController is the input for the domain-controller mode check.
// It verifies that SIA connectors can reach domain controller(s) on the standard
// Kerberos/LDAP ports (389/636/88/464) and on RDP (3389) — a DC is a Windows
// host — and validates the LDAPS and RDP TLS certificates. Each DC may be a
// remote target carrying direct-connection credentials, in which case its
// private FQDN / IPs are resolved (like target mode) and the reachability
// checks run against those.
//
// Example JSON:
//
//	{
//	  "domain_controllers": [
//	    { "hostname": "dc01.corp.local", "os_type": "windows",
//	      "username": "admin", "password": "secret" }
//	  ],
//	  "disable_certificate_check": false
//	}
//
// Only "domain_controllers" is meaningful to set (and within each, only
// "hostname"); everything else is optional. Kerberos/LDAP ports are fixed
// defaults and cannot be overridden here.
type IdsecSIADoctorCheckDomainController struct {
	// DomainControllers lists the DCs to check. Each entry is a target that may
	// carry direct-connection credentials (username/password or SSH key), so the
	// DC's private FQDN / IPs can be resolved over SSH/WinRM and checked, exactly
	// like target mode. When empty, the local machine's hostname (os.Hostname) is
	// used as a single DC with no credentials.
	DomainControllers []IdsecSIADoctorTarget `json:"domain_controllers" mapstructure:"domain_controllers" flag:"domain-controllers" desc:"Array of domain-controller objects. Per-object keys: hostname (required), os_type (linux|darwin|windows), username, password, private_key_path, winrm_protocol (creds enable private-address resolution). Empty = local hostname. Example: [{\"hostname\":\"dc01.corp.local\",\"os_type\":\"windows\",\"username\":\"admin\",\"password\":\"secret\"}]"`

	// ConnectorIDs restricts which connectors perform the checks.
	// When empty, all connectors returned by ListConnectors are used.
	ConnectorIDs []string `json:"connector_ids" mapstructure:"connector_ids" flag:"connector-ids" desc:"Connector IDs to test from. Empty = all connectors."`

	// DisableCertificateCheck turns off LDAPS and RDP certificate validation
	// against the tenant's uploaded certificates. When false (default) each
	// reachable DC's LDAPS and RDP certificates are probed and verified.
	DisableCertificateCheck bool `json:"disable_certificate_check" mapstructure:"disable_certificate_check" flag:"disable-certificate-check" default:"false" desc:"Disable LDAPS/RDP certificate validation against tenant certificates."`

	// ConcurrencyLimit caps how many individual reachability checks run
	// simultaneously. Defaults to 32 when zero.
	ConcurrencyLimit int `json:"concurrency_limit" mapstructure:"concurrency_limit" flag:"concurrency-limit" default:"32" desc:"Max parallel reachability checks (default 32)."`

	// TimeoutSec is the wall-clock limit in seconds for the entire operation.
	// Defaults to 30 s when zero.
	TimeoutSec int `json:"timeout_sec" mapstructure:"timeout_sec" flag:"timeout-sec" default:"30" desc:"Overall operation timeout in seconds (default 30)."`
}
