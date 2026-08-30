package doctor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections"
	sshconn "github.com/cyberark/idsec-sdk-golang/pkg/common/connections/ssh"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections/winrm"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections/connectiondata"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access"
	accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates"
	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca"
	sshcamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/models"
)

// stampDuration records the wall-clock time elapsed since start onto the report.
// Deferred at the top of each Check* method so every return path reports it.
func (s *IdsecSIADoctorService) stampDuration(report **doctormodels.IdsecSIADoctorReport, start time.Time) {
	if report == nil || *report == nil {
		return
	}
	(*report).DurationMs = time.Since(start).Milliseconds()
}

// makeCtx returns a context bounded by timeoutSec (default when non-positive).
func (s *IdsecSIADoctorService) makeCtx(timeoutSec int) (context.Context, context.CancelFunc) {
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}
	return context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
}

// runParallel fans out tasks over a semaphore-bounded goroutine pool and
// collects the results.  When ctx is cancelled (timeout or explicit cancel)
// tasks that are still waiting for a semaphore slot are skipped; tasks that
// are already executing are allowed to finish so the returned slice may
// contain partial results.
func (s *IdsecSIADoctorService) runParallel(
	ctx context.Context,
	concurrencyLimit int,
	tasks []checkFn,
) []doctormodels.IdsecSIADoctorCheckResult {
	if concurrencyLimit <= 0 {
		concurrencyLimit = defaultConcurrencyLimit
	}
	sem := make(chan struct{}, concurrencyLimit)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var allChecks []doctormodels.IdsecSIADoctorCheckResult

	for _, task := range tasks {
		task := task
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Wait for a free slot or context cancellation.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			results := task()
			mu.Lock()
			allChecks = append(allChecks, results...)
			mu.Unlock()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	mu.Lock()
	out := make([]doctormodels.IdsecSIADoctorCheckResult, len(allChecks))
	copy(out, allChecks)
	mu.Unlock()
	return out
}

// NewIdsecSIADoctorService creates a new IdsecSIADoctorService.
func NewIdsecSIADoctorService(authenticators ...auth.IdsecAuth) (*IdsecSIADoctorService, error) {
	svc := &IdsecSIADoctorService{}
	var svcInterface services.IdsecService = svc
	baseService, err := services.NewIdsecBaseService(svcInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", svc.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	svc.IdsecBaseService = baseService
	svc.IdsecISPBaseService = ispBaseService

	svc.accessService, err = access.NewIdsecSIAAccessService(ispBaseAuth)
	if err != nil {
		return nil, err
	}
	svc.sshcaService, err = sshca.NewIdsecSIASSHCAService(ispBaseAuth)
	if err != nil {
		return nil, err
	}
	svc.certificatesService, err = certificates.NewIdsecSIACertificatesService(ispBaseAuth)
	if err != nil {
		return nil, err
	}
	svc.certProbes = newCertProbes()
	return svc, nil
}

func (s *IdsecSIADoctorService) refreshSIAAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ServiceConfig returns the service configuration.
func (s *IdsecSIADoctorService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// ---------------------------------------------------------------------------
// Unified — Check (runs every applicable mode in one pass)
// ---------------------------------------------------------------------------

// Check runs several doctor modes in a single pass and returns one merged
// report (Mode="all"). Client and connector modes always run; target and
// domain-controller modes run when their machine lists are provided, or when
// explicitly requested via req.Modes. Modes run concurrently — each already
// parallelizes internally under its own deadline — and a failure in one mode is
// recorded as a synthetic failed row rather than aborting the others.
func (s *IdsecSIADoctorService) Check(req *doctormodels.IdsecSIADoctorCheck) (report *doctormodels.IdsecSIADoctorReport, err error) {
	s.Logger.Info("Starting SIA doctor unified check")
	defer s.stampDuration(&report, time.Now())

	modes := s.resolveModes(req)
	merged := &doctormodels.IdsecSIADoctorReport{Mode: "all"}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	absorb := func(mode string, r *doctormodels.IdsecSIADoctorReport, e error) {
		mu.Lock()
		defer mu.Unlock()
		if e != nil {
			s.Logger.Warning("SIA doctor %s check failed: %v", mode, e)
			merged.Checks = append(merged.Checks, doctormodels.IdsecSIADoctorCheckResult{
				Mode:        mode,
				Status:      doctormodels.CheckStatusFail,
				Description: fmt.Sprintf("%s check failed: %v", mode, e),
			})
			merged.Summary.Failed++
			merged.Summary.Total++
			return
		}
		if r == nil {
			return
		}
		for i := range r.Checks {
			r.Checks[i].Mode = mode
		}
		merged.Checks = append(merged.Checks, r.Checks...)
		merged.UnreachableTargets = append(merged.UnreachableTargets, r.UnreachableTargets...)
		merged.Connectors = append(merged.Connectors, r.Connectors...)
		merged.Summary.Total += r.Summary.Total
		merged.Summary.Passed += r.Summary.Passed
		merged.Summary.Failed += r.Summary.Failed
		merged.Summary.NA += r.Summary.NA
		merged.Summary.Skipped += r.Summary.Skipped
		merged.Summary.Warnings += r.Summary.Warnings
	}

	launch := func(mode string, fn func() (*doctormodels.IdsecSIADoctorReport, error)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := fn()
			absorb(mode, r, e)
		}()
	}

	for _, mode := range modes {
		switch mode {
		case modeClient:
			launch(modeClient, func() (*doctormodels.IdsecSIADoctorReport, error) {
				return s.CheckClient(req.ClientRequest())
			})
		case modeConnector:
			launch(modeConnector, func() (*doctormodels.IdsecSIADoctorReport, error) {
				return s.CheckConnector(req.ConnectorRequest())
			})
		case modeTarget:
			launch(modeTarget, func() (*doctormodels.IdsecSIADoctorReport, error) {
				return s.CheckTarget(req.TargetRequest())
			})
		case modeDomainController:
			launch(modeDomainController, func() (*doctormodels.IdsecSIADoctorReport, error) {
				return s.CheckDomainController(req.DomainControllerRequest())
			})
		}
	}
	wg.Wait()

	report = merged
	return report, nil
}

// resolveModes returns the ordered, de-duplicated set of modes to run. An
// explicit req.Modes wins (unknown entries are logged and ignored, "dc" is an
// alias for domain-controller); otherwise client + connector always run, plus
// target / domain-controller when their machine lists are provided.
func (s *IdsecSIADoctorService) resolveModes(req *doctormodels.IdsecSIADoctorCheck) []string {
	valid := map[string]bool{
		modeClient: true, modeTarget: true, modeConnector: true, modeDomainController: true,
	}
	seen := map[string]bool{}
	var out []string
	add := func(m string) {
		if valid[m] && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}

	if len(req.Modes) > 0 {
		for _, m := range req.Modes {
			m = strings.ToLower(strings.TrimSpace(m))
			if m == "dc" {
				m = modeDomainController
			}
			if !valid[m] {
				s.Logger.Warning("ignoring unknown doctor mode %q", m)
				continue
			}
			add(m)
		}
	} else {
		add(modeClient)
		add(modeConnector)
		if len(req.Targets) > 0 {
			add(modeTarget)
		}
		if len(req.DomainControllers) > 0 {
			add(modeDomainController)
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return modeRank[out[i]] < modeRank[out[j]] })
	return out
}

// ---------------------------------------------------------------------------
// Mode 1 — Client
// ---------------------------------------------------------------------------

// CheckClient verifies that a client machine can reach every SIA gateway on
// its required port, and checks HTTPS relay reachability when relays are configured.
func (s *IdsecSIADoctorService) CheckClient(req *doctormodels.IdsecSIADoctorCheckClient) (report *doctormodels.IdsecSIADoctorReport, err error) {
	s.Logger.Info("Starting SIA doctor client check")
	defer s.stampDuration(&report, time.Now())

	gwEndpoints, err := s.gatewayEndpoints()
	if err != nil {
		return nil, fmt.Errorf("failed to derive gateway addresses: %w", err)
	}

	timeout := req.ConnectTimeout
	if timeout <= 0 {
		timeout = defaultConnectTimeout
	}

	// Build the full endpoint list once: SIA gateways + active HTTPS relays.
	// Every client dials the same set.
	endpoints := make([]clientEndpoint, 0, len(gwEndpoints))
	for _, ep := range gwEndpoints {
		endpoints = append(endpoints, clientEndpoint{ep.protocol, doctormodels.FlowGW, ep.host, ep.port})
	}
	relayEndpoints, err := s.relayEndpoints()
	if err != nil {
		s.Logger.Warning("failed to list relays for client check: %v", err)
	}
	endpoints = append(endpoints, relayEndpoints...)

	// Optional protocol filter (default: all protocols).
	if protoSet := s.makeProtocolSet(req.Protocols); protoSet != nil {
		filtered := make([]clientEndpoint, 0, len(endpoints))
		for _, ep := range endpoints {
			if protoSet[strings.ToLower(ep.protocol)] {
				filtered = append(filtered, ep)
			}
		}
		endpoints = filtered
	}

	// Reachability: run from each client machine, or on the local machine when
	// no clients are given. Endpoints (local) and clients (remote) are probed in
	// parallel; each remote client further fans out its endpoints over its shared
	// connection. One shared context bounds the whole run.
	ctx, cancel := s.makeCtx(0)
	defer cancel()

	var tasks []checkFn
	if len(req.Clients) == 0 {
		for _, ep := range endpoints {
			ep := ep
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				return []doctormodels.IdsecSIADoctorCheckResult{
					s.localTCPDial(ep.protocol, ep.flow, ep.host, ep.port, timeout),
				}
			})
		}
	} else {
		for _, client := range req.Clients {
			client := client
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				return s.clientChecksFrom(ctx, client, endpoints, timeout)
			})
		}
	}
	checks := s.runParallel(ctx, 0, tasks)

	// SIA proxy TLS certificate validation (enabled by default). SIA fronts its
	// proxies with publicly-trusted (e.g. Let's Encrypt) certificates, so each
	// reachable proxy endpoint's certificate is probed and validated against the
	// host OS/machine trust store — not the tenant certificate store. Gated on
	// reachability so no probe waits on an unreachable endpoint; a system-pool
	// load failure degrades to no cert rows rather than aborting the check.
	//
	// The probe always runs from the local (SDK) host. When remote clients are
	// given, reachability is measured from those machines, so validating a
	// certificate from the local host would mix perspectives — skip it for now
	// and only run the cert check when the client check itself is local.
	if !req.DisableCertificateCheck && len(req.Clients) == 0 {
		roots, poolErr := x509.SystemCertPool()
		if poolErr != nil {
			s.Logger.Warning("failed to load OS certificate pool for SIA proxy certificate check: %v", poolErr)
		} else {
			passed := passedBaseSet(checks)
			checks = append(checks, s.runParallel(ctx, 0, s.siaProxyCertTasks(endpoints, roots, passed))...)
			checks = mergeCertificateResults(checks)
		}
	}

	return s.buildReport("client", checks), nil
}

// relayEndpoints returns the active HTTPS relays as client dial endpoints.
func (s *IdsecSIADoctorService) relayEndpoints() ([]clientEndpoint, error) {
	pages, err := s.accessService.ListRelays()
	if err != nil {
		return nil, err
	}
	var out []clientEndpoint
	for page := range pages {
		for _, relay := range page.Items {
			if relay.StatusCode != accessmodels.HTTPSRelayStatusActive {
				continue
			}
			host := relay.HostName
			if host == "" {
				host = relay.HostIP
			}
			if host == "" {
				continue
			}
			out = append(out, clientEndpoint{"relay", doctormodels.FlowRelay, host, 443})
		}
	}
	return out, nil
}

// clientChecksFrom connects to one client machine and dials every endpoint from
// it. A connection failure yields a single "client-connection" failure row
// rather than one failure per endpoint.
//
// SSH endpoints are dialed in parallel (a fresh session per command is safe),
// but WinRM endpoints are dialed sequentially over the shared connection:
// WinRM's NTLM/Negotiate auth is connection-oriented and stateful, so
// concurrent commands over one connection corrupt the handshake and fail with
// spurious HTTP 401 / "invalid content type" errors. Different clients still
// run concurrently (each has its own connection).
func (s *IdsecSIADoctorService) clientChecksFrom(
	ctx context.Context, client doctormodels.IdsecSIADoctorTarget, endpoints []clientEndpoint, timeout int,
) []doctormodels.IdsecSIADoctorCheckResult {
	osType := strings.ToLower(client.OSType)
	if osType == "" {
		osType = commonmodels.OSTypeLinux
	}
	checkedFrom := "client:" + client.Hostname

	conn, err := s.openConnection(osType, client.Hostname, client.Username, client.Password,
		client.PrivateKeyPath, client.PrivateKeyContents, client.WinRMProtocol)
	if err != nil {
		return []doctormodels.IdsecSIADoctorCheckResult{{
			Protocol:    "client-connection",
			Host:        client.Hostname,
			Status:      doctormodels.CheckStatusFail,
			Description: fmt.Sprintf("failed to connect to client machine: %v", err),
			CheckedFrom: checkedFrom,
		}}
	}
	defer func() { _ = conn.Disconnect() }()

	// WinRM cannot run commands concurrently over one connection — dial serially.
	if osType == commonmodels.OSTypeWindows {
		out := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(endpoints))
		for _, ep := range endpoints {
			out = append(out, s.remoteTCPDial(conn, osType, ep.protocol, ep.flow, ep.host, ep.port, timeout, checkedFrom))
		}
		return out
	}

	tasks := make([]checkFn, 0, len(endpoints))
	for _, ep := range endpoints {
		ep := ep
		tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
			return []doctormodels.IdsecSIADoctorCheckResult{
				s.remoteTCPDial(conn, osType, ep.protocol, ep.flow, ep.host, ep.port, timeout, checkedFrom),
			}
		})
	}
	return s.runParallel(ctx, clientEndpointConcurrency, tasks)
}

// siaProxyProbe returns the certificate probe to use for a SIA proxy endpoint.
// Unlike a target, the client connects to the SIA gateway itself, which fronts
// each protocol with TLS on its published port: rdp / webaccess / relay are
// plain HTTPS (not X.224 RDP), so they use a direct-TLS probe; the database
// gateways reuse their protocol's native (STARTTLS-aware) probe. SSH proxies
// present an SSH host key (no X.509) and are skipped (nil).
func (s *IdsecSIADoctorService) siaProxyProbe(protocol string) certProbe {
	switch protocol {
	case doctormodels.ProtocolSSH:
		return nil
	case doctormodels.ProtocolRDP, "webaccess", "relay":
		return &directTLSProbe{protocol: protocol}
	default:
		return s.certProbes[protocol]
	}
}

// siaProxyCertTasks builds cert-probe tasks for the reachable SIA proxy
// endpoints, validating each proxy's certificate against the OS trust store.
// Gated on the reachability results (passed) so no probe waits on an
// unreachable endpoint. The resulting marker rows are folded onto the matching
// reachability rows by mergeCertificateResults.
func (s *IdsecSIADoctorService) siaProxyCertTasks(
	endpoints []clientEndpoint, roots *x509.CertPool, passed map[protoHost]bool,
) []checkFn {
	var tasks []checkFn
	for _, ep := range endpoints {
		probe := s.siaProxyProbe(ep.protocol)
		if probe == nil {
			continue
		}
		if !passed[protoHost{ep.protocol, strings.ToLower(ep.host)}] {
			continue
		}
		ep, probe := ep, probe
		tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
			s.Logger.Info("SIA proxy cert check %s: probing %s:%d against OS trust store", ep.protocol, ep.host, ep.port)
			v := s.probeSystemCertVerdict(probe, ep.host, ep.port, roots)
			return certMarkers(ep.protocol, ep.port, []string{ep.host}, v)
		})
	}
	return tasks
}

func (s *IdsecSIADoctorService) gatewayEndpoints() ([]gatewayEndpoint, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(s.ISPClient().GetToken(), jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	sub, _ := claims["subdomain"].(string)
	dom, _ := claims["platform_domain"].(string)

	gw := func(svc string) string { return fmt.Sprintf("%s.%s.%s", sub, svc, dom) }

	return []gatewayEndpoint{
		{"ssh", gw("ssh"), 22},
		{"rdp", gw("rdp"), 443},
		{"mysql", gw("mysql"), 3306},
		{"postgres", gw("postgres"), 5432},
		{"mssql", gw("mssql"), 1433},
		{"oracle", gw("oracle"), 2484},
		{"db2", gw("db2"), 50002},
		{"mongo", gw("mongo"), 27017},
		{"webaccess", gw("webaccess"), 443},
		{"k8s", gw("k8s"), 443},
	}, nil
}

func (s *IdsecSIADoctorService) localTCPDial(protocol, flow, host string, port, timeoutSec int) doctormodels.IdsecSIADoctorCheckResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutSec)*time.Second)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return doctormodels.IdsecSIADoctorCheckResult{
			Protocol: protocol, Flow: flow, Host: host, Port: port,
			Status: doctormodels.CheckStatusFail, LatencyMs: latency,
			Description: err.Error(), CheckedFrom: "local",
		}
	}
	_ = conn.Close()
	return doctormodels.IdsecSIADoctorCheckResult{
		Protocol: protocol, Flow: flow, Host: host, Port: port,
		Status: doctormodels.CheckStatusPass, LatencyMs: latency,
		Description: "reachable", CheckedFrom: "local",
	}
}

func (s *IdsecSIADoctorService) remoteTCPDial(
	conn connections.IdsecConnection, osType, protocol, flow, host string, port, timeoutSec int, checkedFrom string,
) doctormodels.IdsecSIADoctorCheckResult {
	var cmd string
	if strings.ToLower(osType) == commonmodels.OSTypeWindows {
		cmd = fmt.Sprintf(
			"$r=(Test-NetConnection -ComputerName '%s' -Port %d -WarningAction SilentlyContinue).TcpTestSucceeded; if($r){'ok'}else{'fail'}",
			host, port,
		)
	} else {
		cmd = fmt.Sprintf(
			"timeout %d bash -c \"</dev/tcp/%s/%d\" 2>/dev/null && echo ok || echo fail",
			timeoutSec, host, port,
		)
	}
	result, err := conn.RunCommand(&connectionsmodels.IdsecConnectionCommand{Command: cmd, IgnoreRC: true})
	status := doctormodels.CheckStatusFail
	description := ""
	if err != nil {
		description = err.Error()
	} else if strings.TrimSpace(result.Stdout) == "ok" {
		status = doctormodels.CheckStatusPass
		description = "reachable"
	} else {
		description = fmt.Sprintf("unreachable (stdout: %s)", strings.TrimSpace(result.Stdout))
	}
	return doctormodels.IdsecSIADoctorCheckResult{
		Protocol: protocol, Flow: flow, Host: host, Port: port,
		Status: status, Description: description, CheckedFrom: checkedFrom,
	}
}

// ---------------------------------------------------------------------------
// Mode 2 — Target
// ---------------------------------------------------------------------------

// CheckTarget verifies that SIA connectors can reach target machines across
// all supported flows and protocols. Connector checks run in parallel, bounded
// by req.ConcurrencyLimit (default 5). An optional req.TimeoutSec wall-clock
// limit can be set; zero means no timeout.
func (s *IdsecSIADoctorService) CheckTarget(req *doctormodels.IdsecSIADoctorCheckTarget) (report *doctormodels.IdsecSIADoctorReport, err error) {
	s.Logger.Info("Starting SIA doctor target check")
	defer s.stampDuration(&report, time.Now())

	connectorIDs, err := s.resolveConnectors(req.ConnectorIDs)
	if err != nil {
		return nil, err
	}

	targets := req.Targets
	if len(targets) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get local hostname: %w", err)
		}
		targets = []doctormodels.IdsecSIADoctorTarget{{Hostname: hostname}}
	}

	protoSet := s.makeProtocolSet(req.Protocols)

	// st holds cross-check reachability state (preferred connector per host +
	// fail-fast unroutable gate).  Shared across all targets since a route is
	// host-scoped.  See reachAnyConnector.
	st := &reachState{}

	var tasks []checkFn
	// staticChecks holds synthetic results that don't need a parallel run
	// (e.g. address-resolution fallback notices, resolved-dc entries).
	var staticChecks []doctormodels.IdsecSIADoctorCheckResult

	// Inspection phase — runs synchronously before the parallel pool (and
	// before the reachability deadline) starts.
	//
	// For every target that has credentials we open ONE SSH/WinRM connection
	// and use it to both (a) resolve the target's private FQDN / IPs so the
	// reachability checks run against the addresses connectors actually route
	// to, and (b) — on Windows targets that need domain-ephemeral checks —
	// discover the writable DC via nltest.  Doing both over a single
	// connection avoids paying the connect handshake twice.  This phase is
	// deliberately kept out of the reachability deadline (makeCtx below is
	// created afterwards) so slow WinRM handshakes never eat into the budget
	// reserved for the connector reachability probes.
	type targetMeta struct {
		target doctormodels.IdsecSIADoctorTarget
		addrs  []string
		dcHost string
	}
	metas := make([]targetMeta, 0, len(targets))

	protoHas := func(p string) bool { return len(protoSet) == 0 || protoSet[p] }

	// Q1: fetch the tenant certificate pool CONCURRENTLY with the SSH/WinRM
	// inspection below. The two touch entirely different systems (the SIA
	// certificates API vs. a direct SSH/WinRM connection to the target) and
	// neither consumes the other's output, so overlapping them hides the
	// cert-list latency behind the connection handshakes. A list failure
	// degrades to unverified rows rather than aborting the target check.
	runCertChecks := !req.DisableCertificateCheck
	var (
		certRoots   *x509.CertPool
		certTenants []tenantCert
		certListErr error
		poolWG      sync.WaitGroup
	)
	if runCertChecks {
		poolWG.Add(1)
		go func() {
			defer poolWG.Done()
			s.Logger.Info("preparing certificate checks")
			certRoots, certTenants, certListErr = s.buildTenantPool()
			if certListErr != nil {
				s.Logger.Warning("failed to list tenant certificates for certificate checks: %v", certListErr)
			}
		}()
	}

	for _, target := range targets {
		needDC := strings.ToLower(target.OSType) == commonmodels.OSTypeWindows &&
			(protoHas(doctormodels.ProtocolRDP) || protoHas(doctormodels.ProtocolMSSQL) || protoHas(doctormodels.ProtocolDB2))

		insp := s.inspectTarget(target, needDC)

		addrsToCheck := insp.addrs
		if len(addrsToCheck) == 0 {
			addrsToCheck = []string{target.Hostname}
		}
		if insp.resolutionFailed {
			staticChecks = append(staticChecks, doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "address-resolution",
				Host:        target.Hostname,
				Status:      doctormodels.CheckStatusSkipped,
				Description: "SSH/WinRM unreachable for address resolution — checks running against given hostname",
				CheckedFrom: "local",
			})
		}
		if insp.addrResult != nil {
			staticChecks = append(staticChecks, *insp.addrResult)
		}
		if insp.dcResult != nil {
			staticChecks = append(staticChecks, *insp.dcResult)
		}

		metas = append(metas, targetMeta{target, addrsToCheck, insp.dcHostname})
	}

	for _, meta := range metas {
		meta := meta
		tasks = append(tasks, s.targetCheckTasks(meta.target, connectorIDs, protoSet, meta.addrs, meta.dcHost, st, req.BatchReachability)...)
		if strings.ToLower(meta.target.OSType) == commonmodels.OSTypeLinux &&
			(len(protoSet) == 0 || protoSet[doctormodels.ProtocolSSH]) {
			target := meta.target
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				return s.sshCACheck(target)
			})
		}
	}

	// Wait for the tenant certificate pool (fetched concurrently with the
	// inspection phase above) before scheduling cert probes.
	poolWG.Wait()

	// Q2: reachability and TLS certificate probing run CONCURRENTLY, each on its
	// own worker pool and deadline. They travel different network paths —
	// reachability is a connector→target test via the SIA API, while a cert probe
	// is a direct doctor-host→target TLS dial — so a slow local dial can no longer
	// starve the reachability probes (or vice versa). Cert probing is no longer
	// gated on connector reachability: the doctor host may retrieve a target's
	// certificate even when no connector can reach it, and mergeCertificateResults
	// simply folds each verdict onto whatever reachability row exists.
	ctxReach, cancelReach := s.makeCtx(req.TimeoutSec)
	defer cancelReach()

	var (
		reachChecks []doctormodels.IdsecSIADoctorCheckResult
		certChecks  []doctormodels.IdsecSIADoctorCheckResult
		phaseWG     sync.WaitGroup
	)
	phaseWG.Add(1)
	go func() {
		defer phaseWG.Done()
		reachChecks = s.runParallel(ctxReach, req.ConcurrencyLimit, tasks)
	}()
	if runCertChecks && certListErr == nil {
		ctxCert, cancelCert := s.makeCtx(req.TimeoutSec)
		defer cancelCert()
		var certTasks []checkFn
		for _, meta := range metas {
			certTasks = append(certTasks, s.certificateCheckTasks(meta.target, meta.addrs, meta.dcHost, protoSet, certRoots, certTenants)...)
		}
		phaseWG.Add(1)
		go func() {
			defer phaseWG.Done()
			certChecks = s.runParallel(ctxCert, req.ConcurrencyLimit, certTasks)
		}()
	}
	phaseWG.Wait()

	// Each task already returns one aggregated "X/N connectors" row per
	// (protocol, flow, host, port); dedupeResults only collapses rows for the
	// rare case of distinct targets resolving to the same host (e.g. a shared DC).
	checks := append(staticChecks, reachChecks...)
	checks = s.dedupeResults(checks)
	checks = s.applyNAStatus(checks, protoSet)

	// Fold TLS certificate trust results (warning when untrusted, note when
	// trusted) onto their matching base protocol rows. When the tenant list
	// could not be fetched, emit unverified markers instead.
	if runCertChecks {
		if certListErr != nil {
			for _, meta := range metas {
				checks = append(checks, s.certListUnavailableRows(meta.target, meta.addrs, meta.dcHost, protoSet, certListErr)...)
			}
		} else {
			checks = append(checks, certChecks...)
		}
	}
	checks = mergeCertificateResults(checks)
	// A target is unreachable when none of the addresses we checked for it
	// produced a passing base-protocol result.  Driven by the target list (not
	// the surviving checks) so a target is surfaced even if its checks were
	// truncated by the timeout, rather than silently vanishing.
	passedHost := map[string]bool{}
	for _, c := range checks {
		// resolved-target is an informational row (Flow == "") that reports the
		// resolved addresses, not a reachability probe — it must not count
		// towards a target being reachable.
		if c.Flow == "" && c.Protocol != "resolved-target" && c.Status == doctormodels.CheckStatusPass {
			passedHost[strings.ToLower(c.Host)] = true
		}
	}
	var unreachable []string
	for _, meta := range metas {
		reachable := false
		for _, a := range meta.addrs {
			if passedHost[strings.ToLower(a)] {
				reachable = true
				break
			}
		}
		if !reachable {
			unreachable = append(unreachable, meta.target.Hostname)
		}
	}
	// Build the report on the full result set so the summary always reflects
	// the true N/A count, even when N/A results are hidden in the Checks list.
	report = s.buildReport("target", checks)
	report.UnreachableTargets = unreachable
	// Each fully-unreachable target counts as a failure in the summary. Its own
	// protocol rows are N/A (protocol simply not reachable), but the target as a
	// whole is a real failure, so surface it in Failed (and Total) rather than
	// letting it hide inside the N/A count.
	report.Summary.Failed += len(unreachable)
	report.Summary.Total += len(unreachable)
	if !req.ShowAll {
		report.Checks = s.filterNA(report.Checks)
	}
	return report, nil
}

// targetCheckTasks returns one check task per (host, port) probe for a target,
// where host is a resolved address (or the discovered DC).
//
// Probes are independent tasks rather than per-host bundles so that a fast
// success is recorded the moment it completes: a Windows target has many closed
// DB/SSH ports that each time out slowly, and bundling them with the passing
// RDP/WinRM probe would let the deadline truncate the whole bundle and discard
// the pass.  Total concurrency is bounded by the runParallel semaphore, so slow
// timeouts on one host cannot serialize in front of another host's probes.  The
// shared reachState still de-duplicates work across probes of the same host via
// the preferred-connector fast-path and the host-level unroutable gate.
//
// addrsToCheck is the set of resolved IPs / FQDNs to test reachability against.
// Pass nil to fall back to t.Hostname (used by connector mode).
//
// discoveredDC is the writable DC hostname already resolved by discoverDCHostname
// (synchronously, before the pool runs).  Pass "" when DC discovery was skipped
// or failed — no DC probes will be emitted.
//
// Per address the function probes:
//   - ONE base connectivity check per requested protocol (Flow = "").
//   - RPC(135) + SMB(445) when any ZSP-local / JIT-capable protocol is active.
//   - WinRM-HTTP(5985) + WinRM-HTTPS(5986) when any ZSP-domain-capable protocol
//     is active.
//
// After the parallel run the caller should invoke applyNAStatus.
func (s *IdsecSIADoctorService) targetCheckTasks(
	t doctormodels.IdsecSIADoctorTarget, connectorIDs []string,
	protocols map[string]bool, addrsToCheck []string,
	discoveredDC string,
	st *reachState,
	batched bool,
) []checkFn {
	s.applyDefaults(&t)

	if len(addrsToCheck) == 0 {
		addrsToCheck = []string{t.Hostname}
	}

	has := func(proto string) bool {
		return len(protocols) == 0 || protocols[strings.ToLower(proto)]
	}

	// RPC/SMB/WinRM extras and DC discovery are Windows-only. Skip them entirely
	// when the target OS is not explicitly set to "windows" to avoid noise for
	// Linux, DB, or cloud targets where these ports are never applicable.
	isWindows := strings.ToLower(t.OSType) == commonmodels.OSTypeWindows
	// RPC(135) + SMB(445) are only needed for RDP: the connector must reach the
	// Windows target to create / elevate a local account.  For database ZSP-local
	// flows the connector connects directly to the DB port (already in PROTOCOLS).
	anyRDPLocalEphemeral := has(doctormodels.ProtocolRDP) && isWindows
	anyDomainEphemeral := (has(doctormodels.ProtocolRDP) || has(doctormodels.ProtocolMSSQL) || has(doctormodels.ProtocolDB2)) && isWindows

	// Group probes per host, preserving first-seen order.
	byHost := map[string][]portCheck{}
	var hostOrder []string
	addProbe := func(host, proto, flow string, port int) {
		if _, ok := byHost[host]; !ok {
			hostOrder = append(hostOrder, host)
		}
		byHost[host] = append(byHost[host], portCheck{proto, flow, port})
	}

	for _, addr := range addrsToCheck {
		// Base checks — one per requested protocol, no flow label.
		// All SIA flows (vaulted, ZSP-local, ZSP-domain, JIT) use the same
		// base port; what differs are the extra ports checked below.
		for _, c := range []struct {
			proto string
			port  int
		}{
			{doctormodels.ProtocolRDP, t.RDPPort},
			{doctormodels.ProtocolSSH, t.SSHPort},
			{doctormodels.ProtocolMSSQL, t.MSSQLPort},
			{doctormodels.ProtocolMySQL, t.MySQLPort},
			{doctormodels.ProtocolMariaDB, t.MariaDBPort},
			{doctormodels.ProtocolMongoDB, t.MongoDBPort},
			{doctormodels.ProtocolPostgreSQL, t.PostgreSQLPort},
			{doctormodels.ProtocolOracle, t.OraclePort},
			{doctormodels.ProtocolDB2, t.DB2Port},
			{doctormodels.ProtocolK8S, t.K8SPort},
		} {
			if has(c.proto) {
				addProbe(addr, c.proto, "", c.port)
			}
		}

		// ZSP local-ephemeral + JIT elevation: connector→target RPC+SMB (RDP only).
		// Both flows require the exact same ports, so they share a single set of
		// checks reported under one combined section.
		if anyRDPLocalEphemeral {
			addProbe(addr, "rpc", doctormodels.FlowZSPLocalEphemeral, zspRPCPort)
			addProbe(addr, "smb", doctormodels.FlowZSPLocalEphemeral, zspSMBPort)
		}

		// ZSP domain-ephemeral extras: WinRM.
		if anyDomainEphemeral {
			addProbe(addr, "winrm-http", doctormodels.FlowZSPDomainEphemeral, t.WinRMHTTPPort)
			addProbe(addr, "winrm-https", doctormodels.FlowZSPDomainEphemeral, t.WinRMHTTPSPort)
		}
	}

	// DC port checks — the DC hostname was already resolved synchronously by
	// discoverDCHostname before the parallel pool started.
	if anyDomainEphemeral && discoveredDC != "" {
		for _, p := range dcPortList {
			addProbe(discoveredDC, p.proto, doctormodels.FlowZSPDomainEphemeral, p.port)
		}
	}

	var tasks []checkFn
	if batched {
		// Alternative path: one task (and one API call per connector) per host,
		// carrying all of that host's ports as a multi-target reachability
		// request. Used to compare throughput against the per-port path below.
		for _, host := range hostOrder {
			host, probes := host, byHost[host]
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				return s.reachAnyConnectorBatch(connectorIDs, st, host, probes)
			})
		}
		return tasks
	}
	for _, host := range hostOrder {
		for _, pc := range byHost[host] {
			host, pc := host, pc
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				return []doctormodels.IdsecSIADoctorCheckResult{
					s.reachAnyConnector(connectorIDs, st, host, pc.proto, pc.flow, pc.port),
				}
			})
		}
	}
	return tasks
}

// applyNAStatus post-processes the already-aggregated results.
//
// protoSet is the set of protocols the caller explicitly requested (may be nil).
//
// Rules applied per host:
//   - Base check (Flow == "") failed:
//     · If the protocol was explicitly requested → keep as "fail" (user wants it).
//     · Otherwise → relabel as "n/a" (protocol simply not running on target).
//   - RPC / SMB extras: "n/a" only when no ZSP-local-capable base proto passed
//     AND none of them were explicitly requested.
//   - WinRM extras: same rule for ZSP-domain-capable protos.
//
// Keyed per host (not per connector): rows are already aggregated across
// connectors, so "base protocol passed" means "reachable by at least one
// connector".
func (s *IdsecSIADoctorService) applyNAStatus(
	checks []doctormodels.IdsecSIADoctorCheckResult,
	protoSet map[string]bool,
) []doctormodels.IdsecSIADoctorCheckResult {
	// Pass 1 — record which base protocols passed per host.
	baseStatus := map[string]map[string]bool{} // host -> proto -> passed
	for _, c := range checks {
		if c.Flow == "" {
			if baseStatus[c.Host] == nil {
				baseStatus[c.Host] = map[string]bool{}
			}
			baseStatus[c.Host][c.Protocol] = c.Status == doctormodels.CheckStatusPass
		}
	}

	// Pass 2 — relabel.
	for i := range checks {
		c := &checks[i]
		switch {
		case c.Protocol == "resolved-target":
			// Informational row — never relabel to N/A (a resolution failure
			// must stay visible so the user knows checks fell back to the
			// given hostname).
		case c.Flow == "":
			if c.Status == doctormodels.CheckStatusFail {
				// Keep as fail only when the protocol was explicitly requested.
				// Otherwise mark N/A so the result is hidden by default — it means
				// the protocol simply isn't running / applicable on that target.
				if len(protoSet) == 0 || !protoSet[c.Protocol] {
					c.Status = doctormodels.CheckStatusNA
				}
			}
		case c.Protocol == "rpc" || c.Protocol == "smb":
			if !s.anyPassedOrRequested(baseStatus[c.Host], zspLocalProtos, protoSet) {
				c.Status = doctormodels.CheckStatusNA
			}
		case c.Protocol == "winrm-http" || c.Protocol == "winrm-https":
			if !s.anyPassedOrRequested(baseStatus[c.Host], zspDomainProtos, protoSet) {
				c.Status = doctormodels.CheckStatusNA
			}
		}
	}
	return checks
}

// anyPassedOrRequested returns true when at least one proto from the list
// either passed its base check, or was explicitly requested (its failure is a
// real problem rather than "protocol not installed").
func (s *IdsecSIADoctorService) anyPassedOrRequested(status map[string]bool, protos []string, protoSet map[string]bool) bool {
	for _, p := range protos {
		if status[p] {
			return true
		}
		if len(protoSet) > 0 && protoSet[p] {
			return true
		}
	}
	return false
}

// reachAnyConnector tests a single (host, protocol, flow, port) tuple and
// returns ONE aggregated result that encodes the "at least one connector must
// reach the target" requirement directly.  On success the result is Pass with
// CheckedFrom "1/N connectors"; if every connector fails it is Fail with
// "0/N connectors" and the last failure message.
//
// Candidate connectors are probed CONCURRENTLY, so a connector whose TCP
// connection times out cannot serialize in front of one that can reach the
// host — the probe's latency is a single timeout, not the sum of them.  We wait
// for all candidates to finish so every timed-out connector is recorded in the
// unroutable gate.
//
// st carries two pieces of cross-check state that make repeated checks against
// the same host cheap and deterministic:
//   - preferred (host -> connectorID): the connector that reached a host is
//     tried for that host's other ports.
//   - unroutable (connector+host): a connector that already timed out / failed to
//     resolve a host cannot reach ANY port on it, so it is skipped without an API
//     call.  After the first probe on a host marks the dead connectors, every
//     subsequent probe on that host only calls the connector(s) that can route,
//     so it returns quickly.
//
// st must not be nil.
func (s *IdsecSIADoctorService) reachAnyConnector(
	connectorIDs []string, st *reachState,
	host, protocol, flow string, port int,
) doctormodels.IdsecSIADoctorCheckResult {
	total := len(connectorIDs)
	r := doctormodels.IdsecSIADoctorCheckResult{
		Protocol: protocol, Flow: flow, Host: host, Port: port,
	}

	// Candidates = connectors not already proven unable to route to this host.
	var candidates []string
	for _, connID := range st.order(connectorIDs, host) {
		if !st.isUnroutable(connID, host) {
			candidates = append(candidates, connID)
		}
	}
	if len(candidates) == 0 {
		r.Status = doctormodels.CheckStatusFail
		r.CheckedFrom = fmt.Sprintf("0/%d connectors", total)
		return r
	}

	pass := func(latency int, desc string) doctormodels.IdsecSIADoctorCheckResult {
		r.Status = doctormodels.CheckStatusPass
		r.LatencyMs = latency
		r.Description = desc
		r.CheckedFrom = fmt.Sprintf("1/%d connectors", total)
		return r
	}

	// Fast path: a connector already proven to route to this host is tried
	// alone (order() places it at candidates[0]).  Reachability is a per-host
	// property — a connector that can route to the host can attempt any of its
	// ports — so a single routable connector's verdict is authoritative:
	//   - reached  -> the port is reachable ("one connector is enough").
	//   - not reached -> the port is closed/filtered on the host; we do NOT
	//     re-probe every other connector.  Fanning out would spend one slow
	//     timeout per remaining connector on a port we already know the host
	//     can't serve, which is exactly what starves other probes past the
	//     deadline.  The "N/N connectors" contract only requires that *some*
	//     connector can reach the target, which this preserves.
	if prefID, ok := st.preferredConnector(host); ok && candidates[0] == prefID {
		reached, latency, desc := s.summarizeReach(s.reachabilityCheck(prefID, host, protocol, flow, port))
		if reached {
			return pass(latency, desc)
		}
		r.Status = doctormodels.CheckStatusFail
		r.Description = desc
		r.CheckedFrom = fmt.Sprintf("0/%d connectors", total)
		return r
	}

	type outcome struct {
		connID  string
		reached bool
		latency int
		desc    string
	}
	ch := make(chan outcome, len(candidates))
	for _, connID := range candidates {
		connID := connID
		go func() {
			reached, latency, desc := s.summarizeReach(s.reachabilityCheck(connID, host, protocol, flow, port))
			ch <- outcome{connID, reached, latency, desc}
		}()
	}

	// Return as soon as ANY connector reaches the host — the "at least one
	// connector" requirement is satisfied the moment the first success arrives,
	// so we must not block on the slowest (timing-out) connector.  Remaining
	// probes drain into the buffered channel and exit on their own.
	var lastDesc string
	for i := 0; i < len(candidates); i++ {
		o := <-ch
		if o.reached {
			st.markPreferred(host, o.connID)
			return pass(o.latency, o.desc)
		}
		lastDesc = o.desc
		// A connector that can't route to the host (timeout / no such host) is
		// recorded so later probes on this host skip it. A closed port
		// ("connection refused") is NOT unroutable — the host is still reachable.
		if s.isUnroutableErr(o.desc) {
			st.markUnroutable(o.connID, host)
		}
	}

	r.Status = doctormodels.CheckStatusFail
	r.Description = lastDesc
	r.CheckedFrom = fmt.Sprintf("0/%d connectors", total)
	return r
}

func routeKey(connID, host string) string { return connID + "\x00" + strings.ToLower(host) }

func (st *reachState) markPreferred(host, connID string) {
	st.preferred.Store(strings.ToLower(host), connID)
}

func (st *reachState) markUnroutable(connID, host string) {
	st.unroutable.Store(routeKey(connID, host), struct{}{})
}

func (st *reachState) isUnroutable(connID, host string) bool {
	_, ok := st.unroutable.Load(routeKey(connID, host))
	return ok
}

// preferredConnector returns the connector already proven to reach the host,
// if one has been recorded.
func (st *reachState) preferredConnector(host string) (string, bool) {
	v, ok := st.preferred.Load(strings.ToLower(host))
	if !ok {
		return "", false
	}
	id, _ := v.(string)
	return id, id != ""
}

// order returns connectorIDs with the host's preferred connector (if any and
// still present) moved to the front.
func (st *reachState) order(connectorIDs []string, host string) []string {
	v, ok := st.preferred.Load(strings.ToLower(host))
	if !ok {
		return connectorIDs
	}
	prefID, _ := v.(string)
	order := make([]string, 0, len(connectorIDs))
	found := false
	for _, c := range connectorIDs {
		if c == prefID {
			found = true
			continue
		}
		order = append(order, c)
	}
	if !found {
		return connectorIDs
	}
	return append([]string{prefID}, order...)
}

// summarizeReach reduces the (usually single) result of one reachabilityCheck
// call to (reached, latencyMs, lastMessage).
func (s *IdsecSIADoctorService) summarizeReach(res []doctormodels.IdsecSIADoctorCheckResult) (bool, int, string) {
	var desc string
	for _, r := range res {
		if r.Status == doctormodels.CheckStatusPass {
			return true, r.LatencyMs, r.Description
		}
		desc = r.Description
	}
	return false, 0, desc
}

// isUnroutableErr reports whether a reachability failure message indicates the
// connector cannot reach the host at all — DNS failure or an explicit routing
// error (no route / network or host unreachable). These are host-level failures
// that let us skip the host's remaining ports.
//
// A bare connect timeout ("i/o timeout" / "context deadline exceeded") is
// deliberately NOT treated as unroutable: a single closed-but-filtered port
// times out identically on an otherwise reachable host (e.g. RDP filtered while
// WinRM is open, or the many closed DB/SSH ports on a Windows box). Marking the
// whole host unroutable on the first timed-out port would skip its genuinely
// open ports and report a reachable target as unreachable.
func (s *IdsecSIADoctorService) isUnroutableErr(desc string) bool {
	d := strings.ToLower(desc)
	switch {
	case strings.Contains(d, "no such host"),
		strings.Contains(d, "no route to host"),
		strings.Contains(d, "network is unreachable"),
		strings.Contains(d, "host is unreachable"):
		return true
	}
	return false
}

// dedupeResults collapses rows that share the same (protocol, flow, host, port)
// key, preferring Pass over Fail over N/A.  Distinct targets that resolve to the
// same host (e.g. two Windows targets in the same domain sharing a DC) would
// otherwise produce duplicate rows.  Insertion order of the first occurrence is
// preserved.
func (s *IdsecSIADoctorService) dedupeResults(checks []doctormodels.IdsecSIADoctorCheckResult) []doctormodels.IdsecSIADoctorCheckResult {
	type key struct {
		protocol, flow, host, checkedFrom string
		port                              int
	}
	rank := func(status string) int {
		switch status {
		case doctormodels.CheckStatusPass:
			return 3
		case doctormodels.CheckStatusFail:
			return 2
		case doctormodels.CheckStatusNA:
			return 1
		default:
			return 0
		}
	}
	idx := make(map[key]int)
	out := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(checks))
	for _, c := range checks {
		k := key{c.Protocol, c.Flow, c.Host, c.CheckedFrom, c.Port}
		if i, ok := idx[k]; ok {
			if rank(c.Status) > rank(out[i].Status) {
				out[i] = c
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, c)
	}
	return out
}

// filterNA removes all N/A results from a slice.
func (s *IdsecSIADoctorService) filterNA(checks []doctormodels.IdsecSIADoctorCheckResult) []doctormodels.IdsecSIADoctorCheckResult {
	out := checks[:0]
	for _, c := range checks {
		if c.Status != doctormodels.CheckStatusNA {
			out = append(out, c)
		}
	}
	return out
}

// inspectTarget opens ONE SSH/WinRM connection to the target (when credentials
// are provided) and uses it to both (a) resolve the target's private FQDN / IPs
// for reachability checks and (b) — on Windows, when needDC — discover the
// writable DC via nltest.  A single connection keeps address resolution and DC
// discovery consistent and avoids paying the connect handshake twice.
//
//   - Credentials present → connect, resolve addresses, and (needDC) run nltest.
//     On connection failure: resolutionFailed=true so the caller falls back to
//     the given hostname and surfaces a notice.
//   - No credentials → nothing is inspected remotely: reachability checks run
//     against the given hostname.  Local DNS resolution is intentionally
//     skipped — cloud/RDS hostnames often resolve to public EC2 addresses via
//     reverse lookup, which are not the addresses connectors route to.
func (s *IdsecSIADoctorService) inspectTarget(t doctormodels.IdsecSIADoctorTarget, needDC bool) targetInspection {
	var insp targetInspection

	setDC := func(status, description, host string) {
		if !needDC {
			return
		}
		insp.dcResult = &doctormodels.IdsecSIADoctorCheckResult{
			Protocol:    "resolved-dc",
			Flow:        doctormodels.FlowZSPDomainEphemeral,
			Host:        host,
			Status:      status,
			Description: description,
			CheckedFrom: "local",
		}
	}

	hasCreds := t.Username != "" || t.PrivateKeyPath != "" || t.PrivateKeyContents != ""
	if !hasCreds {
		setDC(doctormodels.CheckStatusSkipped, "no WinRM credentials provided for DC auto-discovery via nltest", t.Hostname)
		return insp
	}

	osType := strings.ToLower(t.OSType)
	if osType == "" {
		osType = commonmodels.OSTypeLinux
	}
	conn, err := s.openConnection(osType, t.Hostname, t.Username, t.Password,
		t.PrivateKeyPath, t.PrivateKeyContents, t.WinRMProtocol)
	if err != nil {
		s.Logger.Info("target inspection: could not connect to %s: %v", t.Hostname, err)
		insp.resolutionFailed = true
		setDC(doctormodels.CheckStatusFail, fmt.Sprintf("failed to connect for nltest: %v", err), t.Hostname)
		return insp
	}
	defer func() { _ = conn.Disconnect() }()

	// (a) Resolve the target's private FQDN / IPs.
	//
	// The connection method also names the resolution method surfaced in the
	// report row below.
	method := "WinRM"
	var resolveCmd string
	if osType == commonmodels.OSTypeWindows {
		// FQDN lookup is wrapped in try/catch and errors are suppressed so a
		// DNS/socket failure (e.g. [System.Net.Dns]::GetHostEntry can throw a
		// SocketException) never aborts the script before the IP enumeration
		// runs.  The trailing `exit 0` guarantees a zero exit code so the
		// resolved output is always returned rather than discarded as an error.
		resolveCmd = "$ErrorActionPreference='SilentlyContinue'; " +
			"try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch {}; " +
			"Get-NetIPAddress -AddressFamily IPv4 -Type Unicast | " +
			"Where-Object { $_.IPAddress -ne '127.0.0.1' } | " +
			"Select-Object -ExpandProperty IPAddress; exit 0"
	} else {
		method = "SSH"
		resolveCmd = "hostname -f 2>/dev/null; hostname -I 2>/dev/null"
	}
	if result, err := conn.RunCommand(&connectionsmodels.IdsecConnectionCommand{Command: resolveCmd, IgnoreRC: true}); err != nil {
		s.Logger.Info("address resolution: command failed on %s: %v", t.Hostname, err)
		insp.addrResult = &doctormodels.IdsecSIADoctorCheckResult{
			Protocol:    "resolved-target",
			Host:        t.Hostname,
			Status:      doctormodels.CheckStatusFail,
			Description: fmt.Sprintf("private address resolution command failed: %v — checks running against given hostname", err),
			CheckedFrom: "local",
		}
	} else {
		insp.addrs = s.deduplicateAddresses(t.Hostname, strings.Fields(result.Stdout))
		if len(insp.addrs) > 0 {
			insp.addrResult = &doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "resolved-target",
				Host:        strings.Join(insp.addrs, ", "),
				Status:      doctormodels.CheckStatusPass,
				Description: fmt.Sprintf("resolved from %s via %s", t.Hostname, method),
				CheckedFrom: "local",
			}
		} else {
			insp.addrResult = &doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "resolved-target",
				Host:        t.Hostname,
				Status:      doctormodels.CheckStatusFail,
				Description: "no private address resolved — checks running against given hostname",
				CheckedFrom: "local",
			}
		}
	}

	// (b) Discover the writable DC via nltest (Windows domain-ephemeral flows).
	if needDC {
		result, err := conn.RunCommand(&connectionsmodels.IdsecConnectionCommand{
			Command:  "nltest /dsgetdc: /writable 2>&1",
			IgnoreRC: true,
		})
		switch {
		case err != nil:
			setDC(doctormodels.CheckStatusFail, fmt.Sprintf("nltest failed: %v", err), t.Hostname)
		default:
			if dc := s.parseDCFromNltest(result.Stdout); dc == "" {
				setDC(doctormodels.CheckStatusFail, fmt.Sprintf("failed to parse DC hostname from nltest output: %s", result.Stdout), t.Hostname)
			} else {
				insp.dcHostname = dc
				setDC(doctormodels.CheckStatusPass, fmt.Sprintf("resolved from %s via nltest", t.Hostname), dc)
			}
		}
	}

	return insp
}

// deduplicateAddresses returns addr entries that are not equal (case-insensitive)
// to the original hostname, with trailing dots trimmed and blank entries removed.
func (s *IdsecSIADoctorService) deduplicateAddresses(original string, addrs []string) []string {
	seen := map[string]bool{strings.ToLower(original): true}
	var out []string
	for _, a := range addrs {
		a = strings.TrimSuffix(strings.TrimSpace(a), ".")
		key := strings.ToLower(a)
		if a == "" || seen[key] {
			continue
		}
		out = append(out, a)
		seen[key] = true
	}
	return out
}

// makeProtocolSet converts a slice of protocol names into a lookup map.
// Names are normalised to lowercase. Returns nil when the slice is empty,
// which the callers interpret as "all protocols".
func (s *IdsecSIADoctorService) makeProtocolSet(protocols []string) map[string]bool {
	if len(protocols) == 0 {
		return nil
	}
	set := make(map[string]bool, len(protocols))
	for _, p := range protocols {
		set[strings.ToLower(p)] = true
	}
	return set
}

// reachabilityCheck calls TestConnectorReachability for a single (connector, host, port) tuple
// and converts the response into IdsecSIADoctorCheckResult items.
func (s *IdsecSIADoctorService) reachabilityCheck(
	connID, hostname, protocol, flow string, port int,
) []doctormodels.IdsecSIADoctorCheckResult {
	resp, err := s.accessService.TestConnectorReachability(&accessmodels.IdsecSIATestConnectorReachability{
		ConnectorID:           connID,
		TargetHostname:        hostname,
		TargetPort:            port,
		CheckBackendEndpoints: false,
	})
	if err != nil {
		return []doctormodels.IdsecSIADoctorCheckResult{{
			Protocol:    protocol,
			Flow:        flow,
			Host:        hostname,
			Port:        port,
			Status:      doctormodels.CheckStatusFail,
			Description: err.Error(),
			CheckedFrom: "connector:" + connID,
		}}
	}
	return s.reachabilityToResults(connID, protocol, flow, resp)
}

// reachAnyConnectorBatch is the alternative reachability path to reachAnyConnector:
// it tests every (protocol, flow, port) probe for one host in a SINGLE
// TestConnectorReachability call per connector (the request's Targets array
// carries all ports), instead of one API call per port. It returns one
// aggregated result per probe with the same "X/N connectors" semantics — a port
// passes when at least one connector reached it.
func (s *IdsecSIADoctorService) reachAnyConnectorBatch(
	connectorIDs []string, st *reachState, host string, probes []portCheck,
) []doctormodels.IdsecSIADoctorCheckResult {
	total := len(connectorIDs)

	rowFor := func(pc portCheck, status, desc string, latency, n int) doctormodels.IdsecSIADoctorCheckResult {
		return doctormodels.IdsecSIADoctorCheckResult{
			Protocol: pc.proto, Flow: pc.flow, Host: host, Port: pc.port,
			Status: status, Description: desc, LatencyMs: latency,
			CheckedFrom: fmt.Sprintf("%d/%d connectors", n, total),
		}
	}

	// Candidates = connectors not already proven unable to route to this host.
	var candidates []string
	for _, connID := range st.order(connectorIDs, host) {
		if !st.isUnroutable(connID, host) {
			candidates = append(candidates, connID)
		}
	}
	if len(candidates) == 0 {
		results := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(probes))
		for _, pc := range probes {
			results = append(results, rowFor(pc, doctormodels.CheckStatusFail, "", 0, 0))
		}
		return results
	}

	ch := make(chan batchReachOutcome, len(candidates))
	for _, connID := range candidates {
		connID := connID
		go func() { ch <- s.batchReachabilityCheck(connID, host, probes) }()
	}

	// Aggregate across connectors: a port passes if ANY connector reached it.
	agg := make(map[int]portReachResult, len(probes))
	var preferred string
	for i := 0; i < len(candidates); i++ {
		o := <-ch
		if o.anyReached && preferred == "" {
			preferred = o.connID
		}
		if !o.anyReached && o.err != "" && s.isUnroutableErr(o.err) {
			st.markUnroutable(o.connID, host)
		}
		for port, pr := range o.byPort {
			if cur, ok := agg[port]; !ok || (!cur.reached && pr.reached) {
				agg[port] = pr
			}
		}
	}
	if preferred != "" {
		st.markPreferred(host, preferred)
	}

	results := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(probes))
	for _, pc := range probes {
		if pr, ok := agg[pc.port]; ok && pr.reached {
			results = append(results, rowFor(pc, doctormodels.CheckStatusPass, pr.desc, pr.latency, 1))
			continue
		}
		desc := ""
		if pr, ok := agg[pc.port]; ok {
			desc = pr.desc
		}
		results = append(results, rowFor(pc, doctormodels.CheckStatusFail, desc, 0, 0))
	}
	return results
}

// batchReachabilityCheck issues a single TestConnectorReachability call for one
// connector, carrying all of host's ports as a multi-target request, and reduces
// the response into a per-port reached/latency/description map.
func (s *IdsecSIADoctorService) batchReachabilityCheck(
	connID, host string, probes []portCheck,
) batchReachOutcome {
	// De-duplicate ports (e.g. MySQL and MariaDB both use 3306) for the payload.
	seen := make(map[int]bool, len(probes))
	targets := make([]accessmodels.IdsecSIAReachabilityTarget, 0, len(probes))
	for _, pc := range probes {
		if seen[pc.port] {
			continue
		}
		seen[pc.port] = true
		targets = append(targets, accessmodels.IdsecSIAReachabilityTarget{Hostname: host, Port: pc.port})
	}

	resp, err := s.accessService.TestConnectorReachability(&accessmodels.IdsecSIATestConnectorReachability{
		ConnectorID: connID,
		Targets:     targets,
	})
	if err != nil {
		return batchReachOutcome{connID: connID, err: err.Error()}
	}

	byPort := make(map[int]portReachResult, len(resp.Targets))
	anyReached := false
	for _, t := range resp.Targets {
		reached := strings.EqualFold(t.Status, "pass") || strings.EqualFold(t.Status, "ok") || strings.EqualFold(t.Status, "success")
		if reached {
			anyReached = true
		}
		if cur, ok := byPort[t.TargetPort]; !ok || (!cur.reached && reached) {
			byPort[t.TargetPort] = portReachResult{reached: reached, latency: t.LatencyMlsec, desc: t.Description}
		}
	}
	return batchReachOutcome{connID: connID, byPort: byPort, anyReached: anyReached}
}

// sshCACheck connects directly to the target (if credentials are present) and
// runs the SSH CA IsPublicKeyInstalled check.
func (s *IdsecSIADoctorService) sshCACheck(t doctormodels.IdsecSIADoctorTarget) []doctormodels.IdsecSIADoctorCheckResult {
	if t.Username == "" && t.PrivateKeyPath == "" && t.PrivateKeyContents == "" {
		return []doctormodels.IdsecSIADoctorCheckResult{{
			Protocol:    "ssh-ca-key",
			Flow:        doctormodels.FlowZSPSSHCerts,
			Host:        t.Hostname,
			Status:      doctormodels.CheckStatusSkipped,
			Description: "no SSH credentials provided for SSH CA check",
			CheckedFrom: "local",
		}}
	}

	shell := t.Shell
	if shell == "" {
		shell = "bash"
	}
	result, err := s.sshcaService.IsPublicKeyInstalled(&sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
		TargetMachine:      t.Hostname,
		Username:           t.Username,
		Password:           t.Password,
		PrivateKeyPath:     t.PrivateKeyPath,
		PrivateKeyContents: t.PrivateKeyContents,
		Shell:              shell,
	})
	if err != nil {
		return []doctormodels.IdsecSIADoctorCheckResult{{
			Protocol:    "ssh-ca-key",
			Flow:        doctormodels.FlowZSPSSHCerts,
			Host:        t.Hostname,
			Status:      doctormodels.CheckStatusFail,
			Description: err.Error(),
			CheckedFrom: "local",
		}}
	}

	status := doctormodels.CheckStatusFail
	if result.Result {
		status = doctormodels.CheckStatusPass
	}
	return []doctormodels.IdsecSIADoctorCheckResult{{
		Protocol:    "ssh-ca-key",
		Flow:        doctormodels.FlowZSPSSHCerts,
		Host:        t.Hostname,
		Status:      status,
		Description: result.Message,
		CheckedFrom: "local",
	}}
}

// parseDCFromNltest parses `DC: \\hostname` from nltest /dsgetdc output.
func (s *IdsecSIADoctorService) parseDCFromNltest(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DC:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimPrefix(strings.TrimSpace(parts[1]), `\\`)
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Mode 3 — Connector
// ---------------------------------------------------------------------------

// CheckConnector verifies that a connector can reach its backend, and
// optionally that it can also reach the given target machines. Backend and
// target checks run in parallel, bounded by req.ConcurrencyLimit (default 5).
// An optional req.TimeoutSec wall-clock limit can be set; zero means no timeout.
func (s *IdsecSIADoctorService) CheckConnector(req *doctormodels.IdsecSIADoctorCheckConnector) (report *doctormodels.IdsecSIADoctorReport, err error) {
	s.Logger.Info("Starting SIA doctor connector check")
	defer s.stampDuration(&report, time.Now())

	connectorIDs, idFailRows := s.resolveConnectorIDs(req)
	if len(connectorIDs) == 0 {
		if len(idFailRows) > 0 {
			report = s.buildReport("connector", idFailRows)
			report.Connectors = s.connectorInfo(s.referencedConnectorIDs(idFailRows))
			return report, nil
		}
		return nil, fmt.Errorf("no connector IDs could be resolved")
	}

	ctx, cancel := s.makeCtx(req.TimeoutSec)
	defer cancel()

	st := &reachState{}
	var tasks []checkFn
	// Backend reachability is per-connector (that is the point of connector mode).
	for _, connID := range connectorIDs {
		connID := connID
		tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
			return s.backendCheck(connID)
		})
	}
	// Target reachability is aggregated across all connectors ("can any of them
	// reach the target"), same model as CheckTarget.
	for _, target := range req.Targets {
		target := target
		tasks = append(tasks, s.targetCheckTasks(target, connectorIDs, nil, nil, "", st, req.BatchReachability)...)
	}

	checks := append(idFailRows, s.runParallel(ctx, req.ConcurrencyLimit, tasks)...)
	checks = s.dedupeResults(checks)
	report = s.buildReport("connector", checks)
	report.Connectors = s.connectorInfo(s.referencedConnectorIDs(checks))
	return report, nil
}

// referencedConnectorIDs collects the distinct connector IDs referenced by a set
// of check rows (via the "connector:<id>" CheckedFrom prefix), preserving
// first-seen order.
func (s *IdsecSIADoctorService) referencedConnectorIDs(checks []doctormodels.IdsecSIADoctorCheckResult) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, c := range checks {
		id := strings.TrimPrefix(c.CheckedFrom, "connector:")
		if id == c.CheckedFrom || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

// connectorInfo returns descriptive metadata (host / IP / platform / version /
// status) for the given connector IDs, looked up from the tenant connector list.
// Best-effort: on a listing error it returns an ID-only entry per connector so
// the header still identifies the connector, just without the extra detail.
func (s *IdsecSIADoctorService) connectorInfo(ids []string) []doctormodels.IdsecSIADoctorConnectorInfo {
	if len(ids) == 0 {
		return nil
	}
	all, err := s.listAllConnectors()
	if err != nil {
		s.Logger.Warning("failed to list connectors for report headers: %v", err)
	}
	idx := make(map[string]accessmodels.IdsecSIAConnector, len(all))
	for _, c := range all {
		idx[c.ID] = c
	}
	out := make([]doctormodels.IdsecSIADoctorConnectorInfo, 0, len(ids))
	for _, id := range ids {
		c, ok := idx[id]
		if !ok {
			out = append(out, doctormodels.IdsecSIADoctorConnectorInfo{ID: id})
			continue
		}
		out = append(out, doctormodels.IdsecSIADoctorConnectorInfo{
			ID:       c.ID,
			HostName: c.HostName,
			HostIP:   c.HostIP,
			HostType: c.HostType,
			OS:       c.OS,
			Version:  c.Version,
			Status:   c.Status,
			Region:   c.Region,
		})
	}
	return out
}

// backendCheck calls TestConnectorReachability with CheckBackendEndpoints=true.
func (s *IdsecSIADoctorService) backendCheck(connID string) []doctormodels.IdsecSIADoctorCheckResult {
	resp, err := s.accessService.TestConnectorReachability(&accessmodels.IdsecSIATestConnectorReachability{
		ConnectorID:           connID,
		CheckBackendEndpoints: true,
	})
	if err != nil {
		return []doctormodels.IdsecSIADoctorCheckResult{{
			Protocol:    "connector-backend",
			Flow:        doctormodels.FlowBackend,
			Status:      doctormodels.CheckStatusFail,
			Description: err.Error(),
			CheckedFrom: "connector:" + connID,
		}}
	}
	var results []doctormodels.IdsecSIADoctorCheckResult
	for _, be := range resp.Backends {
		status := doctormodels.CheckStatusFail
		if strings.EqualFold(be.Status, "pass") || strings.EqualFold(be.Status, "ok") || strings.EqualFold(be.Status, "success") {
			status = doctormodels.CheckStatusPass
		}
		results = append(results, doctormodels.IdsecSIADoctorCheckResult{
			Protocol:    "connector-backend",
			Flow:        doctormodels.FlowBackend,
			Host:        be.BackendConnectorAddress,
			Status:      status,
			LatencyMs:   be.LatencyMlsec,
			Description: be.Description,
			CheckedFrom: "connector:" + connID,
		})
	}
	return results
}

// resolveConnectorIDs collects the connector IDs to check from the request.
// Explicit ConnectorIDs are used directly, and each ConnectorMachine is
// SSH/WinRM'd to read its connector ID from that machine's local config. When
// req.Local is set the ID is read from this machine's local connector config
// file. When none of those inputs is supplied the default is to check EVERY
// connector in the tenant (Active ones are tested; non-active ones are reported
// as skipped). Per-machine read failures are returned as failure rows rather
// than aborting the run, so one unreachable connector machine does not hide the
// others.
func (s *IdsecSIADoctorService) resolveConnectorIDs(
	req *doctormodels.IdsecSIADoctorCheckConnector,
) ([]string, []doctormodels.IdsecSIADoctorCheckResult) {
	var ids []string
	var failRows []doctormodels.IdsecSIADoctorCheckResult

	ids = append(ids, req.ConnectorIDs...)

	for _, m := range req.ConnectorMachines {
		id, err := s.readConnectorIDFromMachine(m)
		if err != nil {
			failRows = append(failRows, doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "connector-config",
				Flow:        doctormodels.FlowBackend,
				Host:        m.Hostname,
				Status:      doctormodels.CheckStatusFail,
				Description: fmt.Sprintf("failed to read connector ID: %v", err),
				CheckedFrom: "local",
			})
			continue
		}
		ids = append(ids, id)
	}

	hasExplicit := len(req.ConnectorIDs) > 0 || len(req.ConnectorMachines) > 0

	switch {
	case req.Local:
		// Explicitly restrict to the connector installed on this machine.
		id, err := s.readLocalConnectorID()
		if err != nil {
			failRows = append(failRows, doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "connector-config",
				Flow:        doctormodels.FlowBackend,
				Status:      doctormodels.CheckStatusFail,
				Description: fmt.Sprintf("failed to read local connector ID: %v", err),
				CheckedFrom: "local",
			})
		} else {
			ids = append(ids, id)
		}
	case !hasExplicit:
		// Default: check every connector in the tenant.
		all, err := s.listAllConnectors()
		if err != nil {
			failRows = append(failRows, doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "connector-config",
				Flow:        doctormodels.FlowBackend,
				Status:      doctormodels.CheckStatusFail,
				Description: fmt.Sprintf("failed to list connectors: %v", err),
				CheckedFrom: "local",
			})
		} else {
			for _, c := range all {
				if c.ID == "" {
					continue
				}
				if c.Status == accessmodels.ConnectorStatusActive {
					ids = append(ids, c.ID)
					continue
				}
				// Non-active connectors are surfaced but not reachability-tested
				// (a stale/offline connector otherwise just returns HTTP 500).
				status := c.Status
				if status == "" {
					status = "unknown"
				}
				failRows = append(failRows, doctormodels.IdsecSIADoctorCheckResult{
					Protocol:    "connector-backend",
					Flow:        doctormodels.FlowBackend,
					Status:      doctormodels.CheckStatusSkipped,
					Description: fmt.Sprintf("connector not active (status: %s) — reachability not tested", status),
					CheckedFrom: "connector:" + c.ID,
				})
			}
		}
	}

	return s.dedupeStrings(ids), failRows
}

// readConnectorIDFromMachine opens an SSH/WinRM connection to a connector
// machine and parses the connector ID from its local connector config.
func (s *IdsecSIADoctorService) readConnectorIDFromMachine(m doctormodels.IdsecSIADoctorTarget) (string, error) {
	osType := strings.ToLower(m.OSType)
	if osType == "" {
		osType = commonmodels.OSTypeLinux
	}
	conn, err := s.openConnection(osType, m.Hostname, m.Username, m.Password,
		m.PrivateKeyPath, m.PrivateKeyContents, m.WinRMProtocol)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", m.Hostname, err)
	}
	defer func() { _ = conn.Disconnect() }()

	readCmd := unixReadConnectorConfigCmd
	if osType == commonmodels.OSTypeWindows {
		readCmd = winReadConnectorConfigCmd
	}
	result, err := conn.RunCommand(&connectionsmodels.IdsecConnectionCommand{Command: readCmd})
	if err != nil {
		return "", fmt.Errorf("failed to read connector config from %s: %w", m.Hostname, err)
	}
	return s.parseConnectorID(result.Stdout)
}

// readLocalConnectorID reads and parses the connector ID from the local
// connector config file.
func (s *IdsecSIADoctorService) readLocalConnectorID() (string, error) {
	configPath := linuxConnectorConfigPath
	if runtime.GOOS == commonmodels.OSTypeWindows {
		configPath = windowsConnectorConfigPath
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("connector config file not found at %s: %w", configPath, err)
	}
	return s.parseConnectorID(string(data))
}

// parseConnectorID extracts the "Id" field from a connector config JSON body.
func (s *IdsecSIADoctorService) parseConnectorID(configJSON string) (string, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", fmt.Errorf("failed to parse connector config: %w", err)
	}
	id, ok := cfg["Id"].(string)
	if !ok || id == "" {
		return "", fmt.Errorf("connector ID not found in config")
	}
	return id, nil
}

// dedupeStrings returns in with blanks and case-sensitive duplicates removed,
// preserving first-seen order.
func (s *IdsecSIADoctorService) dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// ---------------------------------------------------------------------------
// Mode 4 — Domain Controller
// ---------------------------------------------------------------------------

// CheckDomainController verifies that SIA connectors can reach domain
// controllers on the standard Kerberos/LDAP ports (LDAP 389, LDAPS 636,
// Kerberos 88, kpasswd 464). Each DC may carry direct-connection credentials, in
// which case its private FQDN / IPs are resolved over SSH/WinRM (like target
// mode) and the checks run against those. LDAPS certificates are validated
// against the tenant trust store unless disabled. An optional req.TimeoutSec
// wall-clock limit can be set; zero means no timeout.
func (s *IdsecSIADoctorService) CheckDomainController(req *doctormodels.IdsecSIADoctorCheckDomainController) (report *doctormodels.IdsecSIADoctorReport, err error) {
	s.Logger.Info("Starting SIA doctor domain-controller check")
	defer s.stampDuration(&report, time.Now())

	connectorIDs, err := s.resolveConnectors(req.ConnectorIDs)
	if err != nil {
		return nil, err
	}

	dcs := req.DomainControllers
	if len(dcs) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get local hostname: %w", err)
		}
		dcs = []doctormodels.IdsecSIADoctorTarget{{Hostname: hostname}}
	}

	st := &reachState{}
	var staticChecks []doctormodels.IdsecSIADoctorCheckResult

	// Inspection phase — resolve each DC's private FQDN / IPs when credentials
	// are provided, so reachability runs against the addresses connectors route
	// to.  Kept out of the reachability deadline (started below).
	type dcMeta struct {
		target doctormodels.IdsecSIADoctorTarget
		addrs  []string
	}
	metas := make([]dcMeta, 0, len(dcs))

	// Q1: fetch the tenant certificate pool concurrently with the SSH/WinRM
	// inspection below (independent systems, no shared output).
	runCertChecks := !req.DisableCertificateCheck
	var (
		certRoots   *x509.CertPool
		certTenants []tenantCert
		certListErr error
		poolWG      sync.WaitGroup
	)
	if runCertChecks {
		poolWG.Add(1)
		go func() {
			defer poolWG.Done()
			certRoots, certTenants, certListErr = s.buildTenantPool()
			if certListErr != nil {
				s.Logger.Warning("failed to list tenant certificates for LDAPS certificate check: %v", certListErr)
			}
		}()
	}

	for _, dc := range dcs {
		s.applyDefaults(&dc)
		insp := s.inspectTarget(dc, false)
		addrsToCheck := insp.addrs
		if len(addrsToCheck) == 0 {
			addrsToCheck = []string{dc.Hostname}
		}
		if insp.resolutionFailed {
			staticChecks = append(staticChecks, doctormodels.IdsecSIADoctorCheckResult{
				Protocol:    "address-resolution",
				Host:        dc.Hostname,
				Status:      doctormodels.CheckStatusSkipped,
				Description: "SSH/WinRM unreachable for address resolution — checks running against given hostname",
				CheckedFrom: "local",
			})
		}
		if insp.addrResult != nil {
			staticChecks = append(staticChecks, *insp.addrResult)
		}
		metas = append(metas, dcMeta{dc, addrsToCheck})
	}

	// One task per DC address: its ports run sequentially so the fail-fast gate
	// applies. Ports are the standard Kerberos/LDAP set (no overrides), plus RDP
	// — a domain controller is a Windows host, so its RDP reachability (and, in
	// the second phase below, its RDP TLS certificate) is checked too.
	var tasks []checkFn
	for _, meta := range metas {
		meta := meta
		for _, addr := range meta.addrs {
			addr := addr
			tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
				out := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(dcPortList)+1)
				for _, p := range dcPortList {
					out = append(out, s.reachAnyConnector(connectorIDs, st, addr, p.proto, doctormodels.FlowDC, p.port))
				}
				out = append(out, s.reachAnyConnector(connectorIDs, st, addr, doctormodels.ProtocolRDP, doctormodels.FlowDC, meta.target.RDPPort))
				return out
			})
		}
	}

	// Wait for the tenant certificate pool (fetched concurrently with the
	// inspection phase above) before scheduling cert probes.
	poolWG.Wait()

	// Q2: reachability and TLS cert probing (LDAPS + RDP) run concurrently, each
	// on its own pool and deadline. Cert probing is a direct doctor-host→DC TLS
	// dial, independent of connector→DC reachability, so it is no longer gated on
	// it. Passing dcHost="" makes certificateCheckTasks treat LDAPS as a normal
	// protocol on the DC's own hostname + resolved addresses.
	ctxReach, cancelReach := s.makeCtx(req.TimeoutSec)
	defer cancelReach()

	var (
		reachChecks []doctormodels.IdsecSIADoctorCheckResult
		certChecks  []doctormodels.IdsecSIADoctorCheckResult
		phaseWG     sync.WaitGroup
	)
	phaseWG.Add(1)
	go func() {
		defer phaseWG.Done()
		reachChecks = s.runParallel(ctxReach, req.ConcurrencyLimit, tasks)
	}()
	if runCertChecks && certListErr == nil {
		ctxCert, cancelCert := s.makeCtx(req.TimeoutSec)
		defer cancelCert()
		var certTasks []checkFn
		for _, meta := range metas {
			certTasks = append(certTasks, s.certificateCheckTasks(meta.target, meta.addrs, "", nil, certRoots, certTenants)...)
		}
		phaseWG.Add(1)
		go func() {
			defer phaseWG.Done()
			certChecks = s.runParallel(ctxCert, req.ConcurrencyLimit, certTasks)
		}()
	}
	phaseWG.Wait()

	checks := append(staticChecks, reachChecks...)
	checks = s.dedupeResults(checks)

	if runCertChecks {
		if certListErr != nil {
			for _, meta := range metas {
				checks = append(checks, s.certListUnavailableRows(
					meta.target, meta.addrs, "", nil, certListErr)...)
			}
		} else {
			checks = append(checks, certChecks...)
		}
	}
	checks = mergeCertificateResults(checks)

	return s.buildReport("domain-controller", checks), nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveConnectors returns the IDs of active connectors to use for target/DC modes.
// When ids is non-empty those are returned as-is (explicit caller override).
// Otherwise all connectors with Status == "Active" are returned.
func (s *IdsecSIADoctorService) resolveConnectors(ids []string) ([]string, error) {
	if len(ids) > 0 {
		return ids, nil
	}
	list, err := s.accessService.ListConnectors()
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	if list == nil {
		return nil, nil
	}
	result := make([]string, 0, len(list.Items))
	for _, c := range list.Items {
		if c.Status == accessmodels.ConnectorStatusActive {
			result = append(result, c.ID)
		}
	}
	return result, nil
}

// listAllConnectors returns every connector in the tenant. Used by connector
// mode's default (check-everything) path, which reachability-tests the Active
// ones and reports the rest as skipped.
func (s *IdsecSIADoctorService) listAllConnectors() ([]accessmodels.IdsecSIAConnector, error) {
	list, err := s.accessService.ListConnectors()
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	if list == nil {
		return nil, nil
	}
	return list.Items, nil
}

// reachabilityToResults maps an IdsecSIAReachabilityTestResponse into check results.
func (s *IdsecSIADoctorService) reachabilityToResults(connID, protocol, flow string, resp *accessmodels.IdsecSIAReachabilityTestResponse) []doctormodels.IdsecSIADoctorCheckResult {
	if resp == nil {
		return nil
	}
	results := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(resp.Targets))
	for _, t := range resp.Targets {
		status := doctormodels.CheckStatusFail
		if strings.EqualFold(t.Status, "pass") || strings.EqualFold(t.Status, "ok") || strings.EqualFold(t.Status, "success") {
			status = doctormodels.CheckStatusPass
		}
		results = append(results, doctormodels.IdsecSIADoctorCheckResult{
			Protocol:    protocol,
			Flow:        flow,
			Host:        t.TargetIP,
			Port:        t.TargetPort,
			Status:      status,
			LatencyMs:   t.LatencyMlsec,
			Description: t.Description,
			CheckedFrom: "connector:" + connID,
		})
	}
	return results
}

// buildReport assembles a DoctorReport and computes summary counts.
func (s *IdsecSIADoctorService) buildReport(mode string, checks []doctormodels.IdsecSIADoctorCheckResult) *doctormodels.IdsecSIADoctorReport {
	summary := doctormodels.IdsecSIADoctorSummary{Total: len(checks)}
	for _, c := range checks {
		switch c.Status {
		case doctormodels.CheckStatusPass:
			summary.Passed++
		case doctormodels.CheckStatusFail:
			summary.Failed++
		case doctormodels.CheckStatusNA:
			summary.NA++
		case doctormodels.CheckStatusSkipped:
			summary.Skipped++
		}
		if c.Warning != "" {
			summary.Warnings++
		}
	}
	return &doctormodels.IdsecSIADoctorReport{
		Mode:    mode,
		Checks:  checks,
		Summary: summary,
	}
}

// applyDefaults fills zero-value port fields on a target with spec defaults.
func (s *IdsecSIADoctorService) applyDefaults(t *doctormodels.IdsecSIADoctorTarget) {
	if t.RDPPort == 0 {
		t.RDPPort = defaultRDPPort
	}
	if t.SSHPort == 0 {
		t.SSHPort = defaultSSHPort
	}
	if t.WinRMHTTPPort == 0 {
		t.WinRMHTTPPort = defaultWinRMHTTPPort
	}
	if t.WinRMHTTPSPort == 0 {
		t.WinRMHTTPSPort = defaultWinRMHTTPSPort
	}
	if t.MySQLPort == 0 {
		t.MySQLPort = defaultMySQLPort
	}
	if t.MariaDBPort == 0 {
		t.MariaDBPort = defaultMariaDBPort
	}
	if t.PostgreSQLPort == 0 {
		t.PostgreSQLPort = defaultPostgreSQLPort
	}
	if t.MSSQLPort == 0 {
		t.MSSQLPort = defaultMSSQLPort
	}
	if t.OraclePort == 0 {
		t.OraclePort = defaultOraclePort
	}
	if t.DB2Port == 0 {
		t.DB2Port = defaultDB2Port
	}
	if t.MongoDBPort == 0 {
		t.MongoDBPort = defaultMongoDBPort
	}
	if t.K8SPort == 0 {
		t.K8SPort = defaultK8SPort
	}
}

// openConnection creates and connects an SSH or WinRM connection depending on osType.
func (s *IdsecSIADoctorService) openConnection(
	osType, targetMachine, username, password, privateKeyPath, privateKeyContents, winrmProtocol string,
) (connections.IdsecConnection, error) {
	var conn connections.IdsecConnection
	var details *connectionsmodels.IdsecConnectionDetails

	if strings.ToLower(osType) == commonmodels.OSTypeWindows {
		protocol := winrm.WinRMHTTPSPort
		if strings.ToLower(winrmProtocol) == "http" {
			protocol = winrm.WinRMHTTPPort
		}
		conn = winrm.NewIdsecWinRMConnection()
		details = &connectionsmodels.IdsecConnectionDetails{
			Address:        targetMachine,
			Port:           protocol,
			ConnectionType: connectionsmodels.WinRM,
			Credentials: &connectionsmodels.IdsecConnectionCredentials{
				User:     username,
				Password: password,
			},
			ConnectionData: &connectiondata.IdsecWinRMConnectionData{
				TrustCertificate: true,
				Protocol:         winrmProtocol,
			},
		}
	} else {
		conn = sshconn.NewIdsecSSHConnection()
		details = &connectionsmodels.IdsecConnectionDetails{
			Address:        targetMachine,
			Port:           sshconn.SSHPort,
			ConnectionType: connectionsmodels.SSH,
			Credentials: &connectionsmodels.IdsecConnectionCredentials{
				User:               username,
				Password:           password,
				PrivateKeyFilepath: common.ExpandFolder(privateKeyPath),
				PrivateKeyContents: privateKeyContents,
			},
			ConnectionData: &connectiondata.IdsecSSHConnectionData{},
		}
	}

	if err := conn.Connect(details); err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", targetMachine, err)
	}
	return conn, nil
}
