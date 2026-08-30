package models

// IdsecSIADoctorCheckClient is the input for the client-mode check.
// It verifies that one or more client machines can reach every SIA gateway
// endpoint on its required port, checks HTTPS relay reachability, and validates
// each reachable SIA proxy's TLS certificate against the host OS trust store.
//
// When Clients is empty, checks run directly on the local machine via
// net.DialTimeout. When set, the doctor connects to each client via SSH
// (linux/darwin) or WinRM (windows) — using that client's own credentials —
// and runs the reachability checks from that machine.
//
// Example JSON:
//
//	{
//	  "clients": [
//	    { "hostname": "client1.example.com", "os_type": "linux",
//	      "username": "ec2-user", "private_key_path": "/home/me/id_rsa" }
//	  ],
//	  "connect_timeout": 5
//	}
//
// Every field is optional: an empty body checks the local machine.
type IdsecSIADoctorCheckClient struct {
	// Clients lists the machines to run the gateway / relay reachability checks
	// from. Each entry is a target that may carry direct-connection credentials
	// (username/password or SSH key) and its own OSType. Empty = run the checks
	// on the local machine.
	Clients []IdsecSIADoctorTarget `json:"clients" mapstructure:"clients" flag:"clients" desc:"Array of client-machine objects to run reachability checks from. Per-object keys: hostname (required), os_type (linux|darwin|windows), username, password, private_key_path, winrm_protocol. Empty = local machine. Example: [{\"hostname\":\"client1.example.com\",\"os_type\":\"linux\",\"username\":\"ec2-user\",\"private_key_path\":\"/home/me/id_rsa\"}]"`

	// Protocols filters which SIA gateway / relay protocols are checked. When
	// empty (default) every protocol is checked. Accepted values are the SIA
	// gateway protocols plus the client-only "webaccess" and "relay".
	Protocols []string `json:"protocols" mapstructure:"protocols" flag:"protocols" desc:"Protocols to check (ssh|rdp|mysql|postgres|mssql|oracle|db2|mongo|k8s|webaccess|relay). Empty = all."`

	// ConnectTimeout is the TCP dial timeout in seconds (default 5).
	ConnectTimeout int `json:"connect_timeout" mapstructure:"connect_timeout" flag:"connect-timeout" desc:"TCP dial timeout in seconds." default:"5"`

	// DisableCertificateCheck turns off the SIA proxy TLS certificate validation
	// that otherwise runs for every reachable proxy endpoint. When false
	// (default) each proxy's server certificate is probed and validated against
	// the host OS/machine trust store (SIA proxies use publicly-trusted, e.g.
	// Let's Encrypt, certificates rather than tenant-issued ones).
	DisableCertificateCheck bool `json:"disable_certificate_check" mapstructure:"disable_certificate_check" flag:"disable-certificate-check" default:"false" desc:"Disable SIA proxy TLS certificate validation against the OS/machine trust store."`
}
