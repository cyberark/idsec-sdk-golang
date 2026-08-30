package models

// Protocol name constants — the accepted values for the Protocols filter.
// These strings also appear verbatim in IdsecSIADoctorCheckResult.Protocol.
const (
	ProtocolRDP        = "rdp"
	ProtocolSSH        = "ssh"
	ProtocolMySQL      = "mysql"
	ProtocolMariaDB    = "mariadb"
	ProtocolPostgreSQL = "postgres"
	ProtocolMSSQL      = "mssql"
	ProtocolOracle     = "oracle"
	ProtocolDB2        = "db2"
	ProtocolMongoDB    = "mongo"
	ProtocolK8S        = "k8s"
)

// AllProtocols is the full set of protocol names recognised by the doctor service.
var AllProtocols = []string{
	ProtocolRDP, ProtocolSSH, ProtocolMySQL, ProtocolMariaDB, ProtocolPostgreSQL,
	ProtocolMSSQL, ProtocolOracle, ProtocolDB2, ProtocolMongoDB, ProtocolK8S,
}

// IdsecSIADoctorCheckTarget is the input for the target-mode check.
// For each target, every SIA connector (or the subset in ConnectorIDs) is
// asked to test reachability across all supported flows and protocols.
//
// Example JSON:
//
//	{
//	  "targets": [
//	    { "hostname": "db.example.com" },
//	    { "hostname": "10.0.0.5", "os_type": "windows",
//	      "username": "admin", "password": "secret" }
//	  ],
//	  "protocols": ["rdp", "postgres"],
//	  "show_all": false,
//	  "disable_certificate_check": false
//	}
//
// Only "targets" is required (and within each target, only "hostname"); every
// other field is optional and falls back to the documented default.
type IdsecSIADoctorCheckTarget struct {
	// Targets lists the machines to check. When empty the local machine's
	// hostname (os.Hostname) is used as the single target.
	Targets []IdsecSIADoctorTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"Array of target objects. Per-object keys: hostname (required), os_type (linux|darwin|windows), username, password, private_key_path, winrm_protocol, and <proto>_port overrides (rdp_port, ssh_port, mysql_port, ...). Empty = local hostname. Example: [{\"hostname\":\"db.example.com\"},{\"hostname\":\"10.0.0.5\",\"os_type\":\"windows\",\"username\":\"admin\",\"password\":\"secret\"}]"`

	// Protocols lists the protocols to include in the check (e.g. "rdp", "ssh",
	// "mysql"). When empty, all protocols are checked. Accepted values are the
	// Protocol* constants defined in this package.
	Protocols []string `json:"protocols" mapstructure:"protocols" flag:"protocols" desc:"Protocols to check (rdp|ssh|mysql|mariadb|postgres|mssql|oracle|db2|mongo|k8s). Empty = all."`

	// ConnectorIDs restricts which connectors perform the checks.
	// When empty, all connectors returned by ListConnectors are used.
	ConnectorIDs []string `json:"connector_ids" mapstructure:"connector_ids" flag:"connector-ids" desc:"Connector IDs to test from. Empty = all connectors."`

	// ShowAll includes N/A results in the report. When false (default) protocols
	// that are not running on the target are hidden from the output.
	ShowAll bool `json:"show_all" mapstructure:"show_all" flag:"show-all" desc:"Include N/A (not-applicable) results in output (default false)."`

	// ConcurrencyLimit caps how many per-connector tasks run simultaneously.
	// Defaults to 32 when zero.
	ConcurrencyLimit int `json:"concurrency_limit" mapstructure:"concurrency_limit" flag:"concurrency-limit" default:"32" desc:"Max parallel connector checks (default 32)."`

	// TimeoutSec is the wall-clock limit in seconds for the entire operation.
	// Defaults to 30 s when zero.
	TimeoutSec int `json:"timeout_sec" mapstructure:"timeout_sec" flag:"timeout-sec" default:"30" desc:"Overall operation timeout in seconds (default 30)."`

	// DisableCertificateCheck turns off the per-protocol TLS certificate
	// validation that otherwise runs for every TLS-capable protocol. When false
	// (default), each target's server certificate is probed and verified against
	// the tenant's uploaded certificates.
	DisableCertificateCheck bool `json:"disable_certificate_check" mapstructure:"disable_certificate_check" flag:"disable-certificate-check" default:"false" desc:"Disable per-protocol TLS certificate validation against tenant certificates."`

	// BatchReachability selects the alternative reachability path: instead of one
	// TestConnectorReachability API call per (host, port), a single call per host
	// carries all of that host's ports as a multi-target request. Experimental —
	// used to compare throughput against the default per-port-parallel path.
	BatchReachability bool `json:"batch_reachability" mapstructure:"batch_reachability" flag:"batch-reachability" default:"true" desc:"Send all of a host's ports in one reachability API call instead of one call per port (default true)."`
}

// IdsecSIADoctorTarget describes a single machine to be checked. It is the
// entry type reused by every mode's machine list ("targets", "clients",
// "domain_controllers", "connector_machines").
//
// Only "hostname" is required. The port overrides all default to the standard
// port for that protocol and rarely need to be set. Credentials
// ("username"/"password" or an SSH key, plus "os_type") are optional and only
// used when the mode needs to connect to the machine — e.g. to resolve a
// target's private FQDN/IPs, run the SSH CA check, discover a DC via nltest, or
// read a connector ID. When omitted, those connection-dependent steps are
// skipped and checks run against the given hostname.
//
// Example (a Windows target with credentials for private-address resolution):
//
//	{
//	  "hostname": "10.0.0.5",
//	  "os_type": "windows",
//	  "username": "admin",
//	  "password": "secret",
//	  "winrm_protocol": "https"
//	}
type IdsecSIADoctorTarget struct {
	// Hostname is the FQDN or IP of the target. Required.
	Hostname string `json:"hostname" mapstructure:"hostname" flag:"hostname" validate:"required" desc:"Target hostname or IP (required)."`

	// --- Port overrides (used by TestConnectorReachability calls) ---

	RDPPort        int `json:"rdp_port" mapstructure:"rdp_port" flag:"rdp-port" default:"3389" desc:"RDP port override."`
	SSHPort        int `json:"ssh_port" mapstructure:"ssh_port" flag:"ssh-port" default:"22" desc:"SSH port override."`
	WinRMHTTPPort  int `json:"winrm_http_port" mapstructure:"winrm_http_port" flag:"winrm-http-port" default:"5985" desc:"WinRM HTTP port (ZSP domain ephemeral)."`
	WinRMHTTPSPort int `json:"winrm_https_port" mapstructure:"winrm_https_port" flag:"winrm-https-port" default:"5986" desc:"WinRM HTTPS port (ZSP domain ephemeral)."`
	MySQLPort      int `json:"mysql_port" mapstructure:"mysql_port" flag:"mysql-port" default:"3306" desc:"MySQL port override."`
	MariaDBPort    int `json:"mariadb_port" mapstructure:"mariadb_port" flag:"mariadb-port" default:"3306" desc:"MariaDB port override."`
	PostgreSQLPort int `json:"postgresql_port" mapstructure:"postgresql_port" flag:"postgresql-port" default:"5432" desc:"PostgreSQL port override."`
	MSSQLPort      int `json:"mssql_port" mapstructure:"mssql_port" flag:"mssql-port" default:"1433" desc:"MSSQL port override."`
	OraclePort     int `json:"oracle_port" mapstructure:"oracle_port" flag:"oracle-port" default:"2484" desc:"Oracle port override."`
	DB2Port        int `json:"db2_port" mapstructure:"db2_port" flag:"db2-port" default:"50002" desc:"DB2 port override."`
	MongoDBPort    int `json:"mongodb_port" mapstructure:"mongodb_port" flag:"mongodb-port" default:"27017" desc:"MongoDB port override."`
	K8SPort        int `json:"k8s_port" mapstructure:"k8s_port" flag:"k8s-port" default:"443" desc:"K8S port override."`

	// --- Optional: direct connection credentials for this target ---
	// Required for SSH CA key check (zsp-ssh-certs) and ZSP domain DC auto-discovery.
	// When omitted the dependent checks are reported with Status "skipped".

	// OSType is the target OS: "linux", "darwin", or "windows".
	OSType string `json:"os_type" mapstructure:"os_type" flag:"os-type" desc:"Target OS (linux|darwin|windows). Required for SSH CA check and nltest."`
	// Shell selects the script interpreter for the SSH CA check: "bash" (default) or "kornShell".
	Shell              string `json:"shell" mapstructure:"shell" flag:"shell" default:"bash" desc:"Shell for SSH CA check: bash or kornShell."`
	Username           string `json:"username" mapstructure:"username" flag:"username" desc:"Username for direct connection to target."`
	Password           string `json:"password" mapstructure:"password" flag:"password" desc:"Password for direct connection to target."`
	PrivateKeyPath     string `json:"private_key_path" mapstructure:"private_key_path" flag:"private-key-path" desc:"SSH private key path for direct connection."`
	PrivateKeyContents string `json:"private_key_contents" mapstructure:"private_key_contents" flag:"private-key-contents" desc:"SSH private key PEM contents for direct connection."`
	// WinRMProtocol is used when OSType is "windows": "http" or "https" (default "https").
	WinRMProtocol string `json:"winrm_protocol" mapstructure:"winrm_protocol" flag:"winrm-protocol" default:"https" desc:"WinRM protocol for Windows targets."`
}
