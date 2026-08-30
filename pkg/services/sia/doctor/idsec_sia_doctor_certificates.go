package doctor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

// certProbeTimeoutSec bounds a single TLS certificate probe (dial + negotiation
// + handshake). The overall CheckTarget deadline still governs the whole run.
const certProbeTimeoutSec = 10

// tenantCert pairs a parsed tenant certificate with a human-readable name for
// reporting which certificate a trust chain matched.
type tenantCert struct {
	cert *x509.Certificate
	name string
}

// certVerdict is the certificate validation outcome for a target+protocol.
type certVerdict struct {
	// status is CertStatusTrusted, CertStatusUntrusted, or "" (inconclusive:
	// nothing reachable / no TLS offered).
	status  string
	note    string // populated when trusted
	warning string // populated when untrusted
}

// protoHost keys the reachability outcome of a single base protocol row. Used
// by client mode, where reachability and the SIA-proxy cert probe share the same
// client→proxy network path and gating the probe on reachability is therefore
// legitimate.
type protoHost struct{ proto, host string }

// buildTenantPool fetches the tenant's certificates and returns them as a root
// pool plus the parsed certs (used to name which tenant certificate a chain
// matched). Returns a non-nil error only when the list call itself fails.
func (s *IdsecSIADoctorService) buildTenantPool() (*x509.CertPool, []tenantCert, error) {
	certs, err := s.certificatesService.List()
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	var parsed []tenantCert
	for _, c := range certs {
		body := strings.TrimSpace(c.Body)
		if body == "" {
			continue
		}
		for _, cert := range parsePEMCerts([]byte(body)) {
			pool.AddCert(cert)
			name := c.CertName
			if name == "" {
				name = c.Domain
			}
			if name == "" {
				name = cert.Subject.CommonName
			}
			parsed = append(parsed, tenantCert{cert: cert, name: name})
		}
	}
	return pool, parsed, nil
}

// parsePEMCerts decodes every CERTIFICATE block in pemData.
func parsePEMCerts(pemData []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, cert)
		}
	}
	return out
}

// verifyAgainstTenant verifies leaf up to the tenant root pool, using the
// server-presented certificates as intermediates. Hostname is intentionally not
// checked (the tenant store is a CA bundle); validity dates are enforced.
// Returns the matched tenant certificate's name when a valid chain is found.
func verifyAgainstTenant(
	leaf *x509.Certificate, presented []*x509.Certificate,
	roots *x509.CertPool, tenantCerts []tenantCert,
) (bool, string, error) {
	inter := x509.NewCertPool()
	for _, c := range presented {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return false, "", err
	}
	matched := ""
	if len(chains) > 0 && len(chains[0]) > 0 {
		root := chains[0][len(chains[0])-1]
		matched = tenantCertName(root, tenantCerts)
	}
	return true, matched, nil
}

// verifyAgainstSystemPool verifies leaf up to the host OS trust store, using the
// server-presented certificates as intermediates. Hostname is intentionally not
// checked (mirroring the tenant path); validity dates are enforced. SIA fronts
// its proxies with publicly-trusted (e.g. Let's Encrypt) certificates, so the
// correct trust anchor for a proxy is the machine/OS root store — not the tenant
// store.
func verifyAgainstSystemPool(
	leaf *x509.Certificate, presented []*x509.Certificate, roots *x509.CertPool,
) error {
	inter := x509.NewCertPool()
	for _, c := range presented {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// probeSystemCertVerdict probes host:port with probe and validates the presented
// certificate against the OS trust store (roots). Used for SIA proxy endpoints,
// whose certificates are publicly trusted rather than tenant-issued. An
// inconclusive verdict (empty status) means the endpoint offered no TLS or could
// not be probed.
func (s *IdsecSIADoctorService) probeSystemCertVerdict(
	probe certProbe, host string, port int, roots *x509.CertPool,
) certVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), certProbeTimeoutSec*time.Second)
	defer cancel()

	probeRes, err := probe.Probe(ctx, host, port, certProbeTimeoutSec)
	if err != nil {
		s.Logger.Info("SIA proxy cert probe %s %s:%d inconclusive: %v", probe.Protocol(), host, port, err)
		return certVerdict{}
	}
	if !probeRes.TLSOffered {
		s.Logger.Info("SIA proxy cert probe %s %s:%d inconclusive: endpoint offered no TLS", probe.Protocol(), host, port)
		return certVerdict{}
	}
	leaf := probeRes.Leaf
	if verr := verifyAgainstSystemPool(leaf, probeRes.Intermediates, roots); verr != nil {
		s.Logger.Info("SIA proxy cert probe %s %s:%d untrusted (issuer=%q): %v", probe.Protocol(), host, port, leaf.Issuer.CommonName, verr)
		return certVerdict{
			status: doctormodels.CertStatusUntrusted,
			warning: fmt.Sprintf("SIA proxy TLS certificate not trusted by OS trust store (issuer=%q, expires=%s): %v",
				leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), verr),
		}
	}
	s.Logger.Info("SIA proxy cert probe %s %s:%d trusted by OS trust store (leaf CN=%q)", probe.Protocol(), host, port, leaf.Subject.CommonName)
	return certVerdict{
		status: doctormodels.CertStatusTrusted,
		note: fmt.Sprintf("SIA proxy TLS certificate trusted by OS trust store (issuer=%q, expires=%s)",
			leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02")),
	}
}

// tenantCertName returns the reporting name for the tenant certificate equal to
// root, falling back to the certificate's common name.
func tenantCertName(root *x509.Certificate, tenantCerts []tenantCert) string {
	for _, tc := range tenantCerts {
		if tc.cert.Equal(root) {
			return tc.name
		}
	}
	return root.Subject.CommonName
}

// passedBaseSet indexes the (protocol, host) pairs whose base reachability check
// passed. Client mode gates its SIA-proxy cert probes on this because there the
// cert probe and the reachability check are the same client→proxy dial — unlike
// target/DC mode, where cert probing is a distinct doctor-host→target path and
// is intentionally NOT gated (see certificateCheckTasks).
func passedBaseSet(checks []doctormodels.IdsecSIADoctorCheckResult) map[protoHost]bool {
	m := map[protoHost]bool{}
	for _, c := range checks {
		if c.Status == doctormodels.CheckStatusPass && c.Flow != doctormodels.FlowTLSCertificate {
			m[protoHost{c.Protocol, strings.ToLower(c.Host)}] = true
		}
	}
	return m
}

// certificateCheckTasks returns one cert task per (target, protocol). Each task
// probes the original hostname first — even though it is not itself a
// reachability target — because that is the endpoint the operator connects to
// and it carries the authoritative SNI the tenant certificate was issued for;
// the doctor host can usually reach it directly even when the resolved private
// IP / FQDN is only routable via a connector. The resolved addresses are probed
// as a fallback. The first conclusive verdict wins (so the hostname is
// authoritative when it answers) and is stamped onto marker rows for every
// resolved address.
//
// Probing is deliberately NOT gated on connector→target reachability: a cert
// probe is a direct doctor-host→target TLS dial on a different network path, so
// the doctor host may retrieve a certificate the connectors cannot. Verdicts for
// hosts with no reachability row are simply dropped at merge time.
//
// The markers carry Flow == FlowTLSCertificate and are never displayed
// directly — mergeCertificateResults folds their verdict onto the matching base
// protocol rows and drops them.
func (s *IdsecSIADoctorService) certificateCheckTasks(
	t doctormodels.IdsecSIADoctorTarget, addrs []string, dcHost string, protoSet map[string]bool,
	roots *x509.CertPool, tenantCerts []tenantCert,
) []checkFn {
	s.applyDefaults(&t)
	var tasks []checkFn
	for proto, probe := range s.certProbes {
		if len(protoSet) > 0 && !protoSet[proto] {
			continue
		}
		// In target mode LDAPS is probed on the separately-discovered DC (dcHost);
		// in DC mode (dcHost == "") LDAPS is just another protocol on the DC's own
		// hostname + resolved addresses. Every other protocol always uses the
		// target hostname + resolved addresses.
		hostname, hosts, port := t.Hostname, certHostSet(t.Hostname, addrs), targetPortForProtocol(t, proto)
		if proto == protocolLDAPS && dcHost != "" {
			hostname, hosts = "", []string{dcHost}
		}
		if len(hosts) == 0 {
			continue
		}
		// Cert probing is NOT gated on connector→target reachability: it is a
		// direct doctor-host→target TLS dial on a different network path, so the
		// doctor host may retrieve a certificate even when no connector can reach
		// the target. Probe the original hostname first (authoritative — it
		// carries the SNI the tenant certificate was issued for and is usually
		// directly reachable), then the resolved addresses. The first conclusive
		// verdict wins and is stamped onto every resolved address; at merge time
		// it lands only on the reachability rows that actually exist.
		probeHosts := certHostSet(hostname, hosts)
		proto, probe, hosts, probeHosts, port := proto, probe, hosts, probeHosts, port
		tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
			s.Logger.Info("cert check %s: probing %v (port %d); verdict applies to %v", proto, probeHosts, port, hosts)
			verdict := s.resolveCertVerdict(probe, probeHosts, port, roots, tenantCerts)
			status := verdict.status
			if status == "" {
				status = "inconclusive"
			}
			s.Logger.Info("cert check %s: verdict=%s applied to %v", proto, status, hosts)
			return certMarkers(proto, port, hosts, verdict)
		})
	}
	return tasks
}

// resolveCertVerdict probes hosts in order and returns the first conclusive
// verdict. Callers pass reachable hosts only, so probes connect promptly; an
// inconclusive verdict (empty status) means no host offered TLS.
func (s *IdsecSIADoctorService) resolveCertVerdict(
	probe certProbe, hosts []string, port int,
	roots *x509.CertPool, tenantCerts []tenantCert,
) certVerdict {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if v := s.probeCertVerdict(probe, host, port, roots, tenantCerts); v.status != "" {
			return v
		}
	}
	return certVerdict{}
}

// probeCertVerdict resolves and validates one host's certificate for a protocol.
func (s *IdsecSIADoctorService) probeCertVerdict(
	probe certProbe, host string, port int,
	roots *x509.CertPool, tenantCerts []tenantCert,
) certVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), certProbeTimeoutSec*time.Second)
	defer cancel()

	probeRes, err := probe.Probe(ctx, host, port, certProbeTimeoutSec)
	if err != nil {
		s.Logger.Info("cert probe %s %s:%d inconclusive: %v", probe.Protocol(), host, port, err)
		return certVerdict{}
	}
	if !probeRes.TLSOffered {
		s.Logger.Info("cert probe %s %s:%d inconclusive: endpoint offered no TLS", probe.Protocol(), host, port)
		return certVerdict{}
	}
	leaf := probeRes.Leaf
	trusted, matched, verr := verifyAgainstTenant(leaf, probeRes.Intermediates, roots, tenantCerts)
	if trusted {
		s.Logger.Info("cert probe %s %s:%d trusted via %q (leaf CN=%q)", probe.Protocol(), host, port, matched, leaf.Subject.CommonName)
		return certVerdict{
			status: doctormodels.CertStatusTrusted,
			note: fmt.Sprintf("TLS certificate trusted via %q (expires %s)",
				matched, leaf.NotAfter.UTC().Format("2006-01-02")),
		}
	}
	detail := "no trust chain to any tenant certificate"
	if verr != nil {
		detail = verr.Error()
	}
	s.Logger.Info("cert probe %s %s:%d untrusted (issuer=%q): %s", probe.Protocol(), host, port, leaf.Issuer.CommonName, detail)
	return certVerdict{
		status: doctormodels.CertStatusUntrusted,
		warning: fmt.Sprintf("TLS certificate not trusted (issuer=%q, expires=%s): %s",
			leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), detail),
	}
}

// certMarkers builds one marker row per host carrying the shared verdict.
func certMarkers(proto string, port int, hosts []string, v certVerdict) []doctormodels.IdsecSIADoctorCheckResult {
	out := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, doctormodels.IdsecSIADoctorCheckResult{
			Protocol:    proto,
			Flow:        doctormodels.FlowTLSCertificate,
			Host:        host,
			Port:        port,
			Status:      doctormodels.CheckStatusNA,
			CheckedFrom: "local",
			CertStatus:  v.status,
			Description: v.note,
			Warning:     v.warning,
		})
	}
	return out
}

// certHostSet returns the hostname followed by the resolved addresses,
// de-duplicated (case-insensitive) with blanks removed.
func certHostSet(hostname string, addrs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range append([]string{hostname}, addrs...) {
		if h == "" {
			continue
		}
		k := strings.ToLower(h)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}
	return out
}

// certListUnavailableRows emits one cert marker row per (host, protocol)
// reporting that trust could not be verified because the tenant certificate
// list could not be fetched.
func (s *IdsecSIADoctorService) certListUnavailableRows(
	t doctormodels.IdsecSIADoctorTarget, addrs []string, dcHost string, protoSet map[string]bool, listErr error,
) []doctormodels.IdsecSIADoctorCheckResult {
	s.applyDefaults(&t)
	warning := fmt.Sprintf("TLS certificate trust not verified: could not list tenant certificates: %v", listErr)
	var out []doctormodels.IdsecSIADoctorCheckResult
	for proto := range s.certProbes {
		if len(protoSet) > 0 && !protoSet[proto] {
			continue
		}
		hosts := certHostSet(t.Hostname, addrs)
		if proto == protocolLDAPS && dcHost != "" {
			hosts = []string{dcHost}
		}
		out = append(out, certMarkers(proto, targetPortForProtocol(t, proto), hosts, certVerdict{
			status:  doctormodels.CertStatusUnverified,
			warning: warning,
		})...)
	}
	return out
}

// mergeCertificateResults folds each cert marker row (Flow == FlowTLSCertificate)
// onto the matching reachability row (same protocol + host, any flow — WinRM
// HTTPS and LDAPS live under the domain-ephemeral flow, not the empty base
// flow): an untrusted result attaches its Warning, a trusted result appends its
// note to the row's Description. The marker rows are then dropped. Markers with
// no outcome, or with no matching row, are discarded.
func mergeCertificateResults(checks []doctormodels.IdsecSIADoctorCheckResult) []doctormodels.IdsecSIADoctorCheckResult {
	type key struct{ proto, host string }
	type certOutcome struct {
		status  string
		warning string
		note    string
	}
	outcomes := map[key]certOutcome{}
	out := make([]doctormodels.IdsecSIADoctorCheckResult, 0, len(checks))
	for _, c := range checks {
		if c.Flow == doctormodels.FlowTLSCertificate {
			if c.CertStatus != "" || c.Warning != "" || c.Description != "" {
				outcomes[key{c.Protocol, strings.ToLower(c.Host)}] = certOutcome{status: c.CertStatus, warning: c.Warning, note: c.Description}
			}
			continue
		}
		out = append(out, c)
	}
	for i := range out {
		c := &out[i]
		o, ok := outcomes[key{c.Protocol, strings.ToLower(c.Host)}]
		if !ok {
			continue
		}
		c.CertStatus = o.status
		if o.warning != "" {
			c.Warning = o.warning
		}
		if o.note != "" {
			if c.Description == "" || c.Description == "reachable" {
				c.Description = o.note
			} else {
				c.Description = c.Description + "; " + o.note
			}
		}
	}
	return out
}

// targetPortForProtocol returns the port for proto on t. applyDefaults must have
// been called on t first.
func targetPortForProtocol(t doctormodels.IdsecSIADoctorTarget, proto string) int {
	switch proto {
	case doctormodels.ProtocolRDP:
		return t.RDPPort
	case doctormodels.ProtocolMSSQL:
		return t.MSSQLPort
	case doctormodels.ProtocolMySQL:
		return t.MySQLPort
	case doctormodels.ProtocolMariaDB:
		return t.MariaDBPort
	case doctormodels.ProtocolPostgreSQL:
		return t.PostgreSQLPort
	case doctormodels.ProtocolOracle:
		return t.OraclePort
	case doctormodels.ProtocolDB2:
		return t.DB2Port
	case doctormodels.ProtocolMongoDB:
		return t.MongoDBPort
	case doctormodels.ProtocolK8S:
		return t.K8SPort
	case protocolWinRMHTTPS:
		return t.WinRMHTTPSPort
	case protocolLDAPS:
		return ldapsPort
	default:
		return 0
	}
}
