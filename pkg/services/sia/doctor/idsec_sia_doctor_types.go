package doctor

import (
	"sync"

	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates"
	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca"
)

const (
	zspRPCPort = 135
	zspSMBPort = 445

	defaultConnectTimeout   = 5
	defaultConcurrencyLimit = 32
	defaultTimeoutSec       = 60

	defaultRDPPort        = 3389
	defaultSSHPort        = 22
	defaultWinRMHTTPPort  = 5985
	defaultWinRMHTTPSPort = 5986
	defaultMySQLPort      = 3306
	defaultMariaDBPort    = 3306
	defaultPostgreSQLPort = 5432
	defaultMSSQLPort      = 1433
	defaultOraclePort     = 2484
	defaultDB2Port        = 50002
	defaultMongoDBPort    = 27017
	defaultK8SPort        = 443
)

// Doctor mode names accepted by the unified Check command.
const (
	modeClient           = "client"
	modeTarget           = "target"
	modeConnector        = "connector"
	modeDomainController = "domain-controller"
)

// clientEndpointConcurrency bounds how many endpoints an SSH client dials in
// parallel over its single connection. Kept modest to avoid opening too many
// concurrent sessions at once.
const clientEndpointConcurrency = 8

const (
	linuxConnectorConfigPath   = "/opt/cyberark/connector/connector.config.json"
	windowsConnectorConfigPath = `C:\Program Files\CyberArk\DPAConnector\connector.config.json`
	winReadConnectorConfigCmd  = `Get-Content -Path "C:\Program Files\CyberArk\DPAConnector\connector.config.json"`
	unixReadConnectorConfigCmd = "sudo cat /opt/cyberark/connector/connector.config.json"
)

// modeRank gives each mode a stable position so the merged report is banded in
// a consistent order regardless of goroutine completion order.
var modeRank = map[string]int{
	modeClient:           0,
	modeConnector:        1,
	modeTarget:           2,
	modeDomainController: 3,
}

// zspLocalProtos lists protocols whose ZSP-local / JIT flows require RPC + SMB.
// Only RDP triggers these extras: for databases the connector connects directly
// to the DB port to create ephemeral users, so no RPC/SMB is needed.
var zspLocalProtos = []string{doctormodels.ProtocolRDP}

// zspDomainProtos lists protocols whose ZSP-domain flow requires WinRM.
var zspDomainProtos = []string{doctormodels.ProtocolRDP, doctormodels.ProtocolMSSQL, doctormodels.ProtocolDB2}

// dcPortList defines the connector→DC ports required for ZSP domain-ephemeral flows.
var dcPortList = []struct {
	proto string
	port  int
}{
	{"ldap", 389},
	{"ldaps", 636},
	{"kerberos", 88},
	{"kpasswd", 464},
}

// checkFn is the unit-of-work type for the parallel runner.
type checkFn = func() []doctormodels.IdsecSIADoctorCheckResult

// IdsecSIADoctorService implements SIA compatibility check-ups across four modes:
// client, target, connector, and domain-controller.
type IdsecSIADoctorService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	accessService       *access.IdsecSIAAccessService
	sshcaService        *sshca.IdsecSIASSHCAService
	certificatesService *certificates.IdsecSIACertificatesService
	certProbes          map[string]certProbe
}

// clientEndpoint is one destination every client machine dials: a SIA gateway
// or an active HTTPS relay.
type clientEndpoint struct {
	protocol string
	flow     string
	host     string
	port     int
}

// gatewayEndpoint is a single SIA gateway address+port pair.
type gatewayEndpoint struct {
	protocol string
	host     string
	port     int
}

// portCheck is one (protocol, flow, port) reachability probe against a host.
type portCheck struct {
	proto string
	flow  string
	port  int
}

// reachState is shared, concurrency-safe cross-check state for a single Check*
// invocation.  See reachAnyConnector for how it is used.
type reachState struct {
	preferred  sync.Map // host -> connectorID that reached it
	unroutable sync.Map // "connID\x00host" -> struct{} : connector cannot route to host
}

// targetInspection is everything a single management connection to a target
// yields: the resolved addresses to route-check, whether that connection
// failed, and (for Windows domain-ephemeral flows) the discovered writable DC.
type targetInspection struct {
	// addrs are the resolved private IPs / FQDNs to run reachability checks
	// against.  Empty means "fall back to the given hostname".
	addrs []string
	// resolutionFailed is true when credentials were provided but the
	// SSH/WinRM connection failed, so the caller must surface a visible notice
	// and fall back to the given hostname.
	resolutionFailed bool
	// addrResult is the "resolved-target" row surfacing the private FQDN / IPs
	// the reachability checks actually run against.  Set only when a management
	// connection was established (credentials present + connect succeeded);
	// nil when resolution was not attempted or the connection failed (the
	// caller emits the address-resolution fallback notice in that case).
	addrResult *doctormodels.IdsecSIADoctorCheckResult
	// dcHostname is the writable DC discovered via nltest (Windows only).
	dcHostname string
	// dcResult is the "resolved-dc" row; set only when DC discovery was
	// requested (needDC).  nil otherwise.
	dcResult *doctormodels.IdsecSIADoctorCheckResult
}

// portReachResult is one port's reachability outcome from a batched call.
type portReachResult struct {
	reached bool
	latency int
	desc    string
}

// batchReachOutcome is one connector's response to a batched reachability call:
// a per-port result map plus whether the connector reached any port (used to
// mark it the host's preferred connector) or errored (unroutable gate).
type batchReachOutcome struct {
	connID     string
	byPort     map[int]portReachResult
	anyReached bool
	err        string
}
