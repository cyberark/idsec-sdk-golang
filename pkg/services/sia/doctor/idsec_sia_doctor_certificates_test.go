package doctor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

func TestVerifyAgainstTenant(t *testing.T) {
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "svc.example.com")
	tenant := []tenantCert{{cert: ca, name: "acme-root"}}

	t.Run("trusted", func(t *testing.T) {
		ok, matched, err := verifyAgainstTenant(leaf, nil, poolWith(ca), tenant)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, "acme-root", matched)
	})

	t.Run("untrusted_unknown_root", func(t *testing.T) {
		otherCA, _ := newCA(t)
		ok, _, err := verifyAgainstTenant(leaf, nil, poolWith(otherCA), nil)
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("expired_leaf", func(t *testing.T) {
		_, expired := newLeafValidity(t, ca, caKey, "old.example.com",
			time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		ok, _, err := verifyAgainstTenant(expired, nil, poolWith(ca), tenant)
		require.Error(t, err)
		require.False(t, ok)
	})
}

func TestVerifyAgainstSystemPool(t *testing.T) {
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "proxy.example.com")

	require.NoError(t, verifyAgainstSystemPool(leaf, nil, poolWith(ca)))

	otherCA, _ := newCA(t)
	require.Error(t, verifyAgainstSystemPool(leaf, nil, poolWith(otherCA)))
}

func TestTenantCertName(t *testing.T) {
	ca, _ := newCA(t)
	other, _ := newCA(t)
	tenant := []tenantCert{{cert: ca, name: "friendly-name"}}

	require.Equal(t, "friendly-name", tenantCertName(ca, tenant))
	// Fallback to the certificate's common name when not in the tenant list.
	require.Equal(t, other.Subject.CommonName, tenantCertName(other, tenant))
}

func TestPassedBaseSet(t *testing.T) {
	checks := []doctormodels.IdsecSIADoctorCheckResult{
		{Protocol: "rdp", Host: "Host.A", Status: doctormodels.CheckStatusPass},
		{Protocol: "ssh", Host: "host.b", Status: doctormodels.CheckStatusFail},
		// TLS-certificate marker rows must be ignored.
		{Protocol: "rdp", Host: "host.c", Status: doctormodels.CheckStatusPass, Flow: doctormodels.FlowTLSCertificate},
	}
	set := passedBaseSet(checks)
	require.True(t, set[protoHost{"rdp", "host.a"}], "host key must be lowercased")
	require.False(t, set[protoHost{"ssh", "host.b"}])
	require.False(t, set[protoHost{"rdp", "host.c"}])
}

func TestCertHostSet(t *testing.T) {
	got := certHostSet("Host.Example", []string{"", "10.0.0.1", "host.example", "10.0.0.1"})
	require.Equal(t, []string{"Host.Example", "10.0.0.1"}, got,
		"hostname first, blanks dropped, case-insensitive dedupe")
}

func TestCertMarkers(t *testing.T) {
	markers := certMarkers("rdp", 3389, []string{"h1", "h2"}, certVerdict{
		status: doctormodels.CertStatusTrusted, note: "trusted note",
	})
	require.Len(t, markers, 2)
	for _, m := range markers {
		require.Equal(t, doctormodels.FlowTLSCertificate, m.Flow)
		require.Equal(t, doctormodels.CheckStatusNA, m.Status)
		require.Equal(t, doctormodels.CertStatusTrusted, m.CertStatus)
		require.Equal(t, "trusted note", m.Description)
		require.Equal(t, 3389, m.Port)
	}
}

func TestMergeCertificateResults(t *testing.T) {
	checks := []doctormodels.IdsecSIADoctorCheckResult{
		{Protocol: "rdp", Host: "H1", Status: doctormodels.CheckStatusPass, Description: "reachable"},
		{Protocol: "mysql", Host: "H2", Status: doctormodels.CheckStatusPass, Description: "reachable"},
		{Protocol: "oracle", Host: "H3", Status: doctormodels.CheckStatusPass},
		// Trusted marker → folds a note onto the rdp row.
		{Protocol: "rdp", Host: "h1", Flow: doctormodels.FlowTLSCertificate,
			CertStatus: doctormodels.CertStatusTrusted, Description: "cert ok"},
		// Untrusted marker → attaches a warning onto the mysql row.
		{Protocol: "mysql", Host: "h2", Flow: doctormodels.FlowTLSCertificate,
			CertStatus: doctormodels.CertStatusUntrusted, Warning: "bad cert"},
		// Marker with no matching reachability row → dropped silently.
		{Protocol: "db2", Host: "nowhere", Flow: doctormodels.FlowTLSCertificate,
			CertStatus: doctormodels.CertStatusTrusted, Description: "orphan"},
	}

	out := mergeCertificateResults(checks)

	// All marker rows are removed; only the three base rows remain.
	require.Len(t, out, 3)
	byProto := map[string]doctormodels.IdsecSIADoctorCheckResult{}
	for _, c := range out {
		require.NotEqual(t, doctormodels.FlowTLSCertificate, c.Flow)
		byProto[c.Protocol] = c
	}

	require.Equal(t, doctormodels.CertStatusTrusted, byProto["rdp"].CertStatus)
	require.Equal(t, "cert ok", byProto["rdp"].Description, "note replaces the plain 'reachable' description")

	require.Equal(t, doctormodels.CertStatusUntrusted, byProto["mysql"].CertStatus)
	require.Equal(t, "bad cert", byProto["mysql"].Warning)

	// oracle had no marker → untouched.
	require.Empty(t, byProto["oracle"].CertStatus)
}

func TestTargetPortForProtocol(t *testing.T) {
	var target doctormodels.IdsecSIADoctorTarget
	newTestService().applyDefaults(&target)

	require.Equal(t, defaultRDPPort, targetPortForProtocol(target, doctormodels.ProtocolRDP))
	require.Equal(t, defaultMongoDBPort, targetPortForProtocol(target, doctormodels.ProtocolMongoDB))
	require.Equal(t, defaultWinRMHTTPSPort, targetPortForProtocol(target, protocolWinRMHTTPS))
	require.Equal(t, ldapsPort, targetPortForProtocol(target, protocolLDAPS))
	require.Equal(t, 0, targetPortForProtocol(target, doctormodels.ProtocolSSH))
}

func TestProbeCertVerdict(t *testing.T) {
	svc := newTestService()
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "svc.example.com")
	roots := poolWith(ca)
	tenant := []tenantCert{{cert: ca, name: "acme"}}

	t.Run("trusted", func(t *testing.T) {
		p := &fakeProbe{proto: "rdp", res: &certProbeResult{Leaf: leaf, TLSOffered: true}}
		v := svc.probeCertVerdict(p, "h", 3389, roots, tenant)
		require.Equal(t, doctormodels.CertStatusTrusted, v.status)
		require.NotEmpty(t, v.note)
	})

	t.Run("untrusted", func(t *testing.T) {
		other, _ := newCA(t)
		p := &fakeProbe{proto: "rdp", res: &certProbeResult{Leaf: leaf, TLSOffered: true}}
		v := svc.probeCertVerdict(p, "h", 3389, poolWith(other), nil)
		require.Equal(t, doctormodels.CertStatusUntrusted, v.status)
		require.NotEmpty(t, v.warning)
	})

	t.Run("no_tls", func(t *testing.T) {
		p := &fakeProbe{proto: "mysql", res: &certProbeResult{TLSOffered: false}}
		v := svc.probeCertVerdict(p, "h", 3306, roots, tenant)
		require.Empty(t, v.status)
	})

	t.Run("probe_error", func(t *testing.T) {
		p := &fakeProbe{proto: "mysql", err: context.DeadlineExceeded}
		v := svc.probeCertVerdict(p, "h", 3306, roots, tenant)
		require.Empty(t, v.status)
	})
}

func TestResolveCertVerdict_FirstConclusiveWins(t *testing.T) {
	svc := newTestService()
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "svc.example.com")

	// Probe offers no TLS → every host is inconclusive → empty verdict.
	noTLS := &fakeProbe{proto: "oracle", res: &certProbeResult{TLSOffered: false}}
	require.Empty(t, svc.resolveCertVerdict(noTLS, []string{"", "h1", "h2"}, 2484, poolWith(ca), nil).status)

	// Probe returns a trusted cert → first non-blank host yields the verdict.
	trusted := &fakeProbe{proto: "oracle", res: &certProbeResult{Leaf: leaf, TLSOffered: true}}
	v := svc.resolveCertVerdict(trusted, []string{"", "h1"}, 2484, poolWith(ca), []tenantCert{{cert: ca, name: "acme"}})
	require.Equal(t, doctormodels.CertStatusTrusted, v.status)
}

func TestProbeSystemCertVerdict(t *testing.T) {
	svc := newTestService()
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "proxy.example.com")

	trusted := &fakeProbe{proto: "oracle", res: &certProbeResult{Leaf: leaf, TLSOffered: true}}
	require.Equal(t, doctormodels.CertStatusTrusted,
		svc.probeSystemCertVerdict(trusted, "h", 2484, poolWith(ca)).status)

	other, _ := newCA(t)
	require.Equal(t, doctormodels.CertStatusUntrusted,
		svc.probeSystemCertVerdict(trusted, "h", 2484, poolWith(other)).status)

	noTLS := &fakeProbe{proto: "oracle", res: &certProbeResult{TLSOffered: false}}
	require.Empty(t, svc.probeSystemCertVerdict(noTLS, "h", 2484, poolWith(ca)).status)
}

func TestCertificateCheckTasks_PropagatesVerdictToAllHosts(t *testing.T) {
	svc := newTestService()
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "target.example.com")
	// Inject a single controlled probe so the task set is deterministic.
	svc.certProbes = map[string]certProbe{
		doctormodels.ProtocolRDP: &fakeProbe{proto: doctormodels.ProtocolRDP, res: &certProbeResult{Leaf: leaf, TLSOffered: true}},
	}

	target := doctormodels.IdsecSIADoctorTarget{Hostname: "target.example.com"}
	tasks := svc.certificateCheckTasks(target, []string{"10.0.0.9"}, "", nil, poolWith(ca), []tenantCert{{cert: ca, name: "acme"}})
	require.Len(t, tasks, 1)

	markers := tasks[0]()
	require.Len(t, markers, 2, "verdict applies to hostname + resolved address")
	for _, m := range markers {
		require.Equal(t, doctormodels.ProtocolRDP, m.Protocol)
		require.Equal(t, doctormodels.CertStatusTrusted, m.CertStatus)
	}
}

func TestCertificateCheckTasks_LDAPSUsesDCHost(t *testing.T) {
	svc := newTestService()
	ca, caKey := newCA(t)
	_, leaf := newLeaf(t, ca, caKey, "dc.example.com")
	svc.certProbes = map[string]certProbe{
		protocolLDAPS: &fakeProbe{proto: protocolLDAPS, res: &certProbeResult{Leaf: leaf, TLSOffered: true}},
	}

	target := doctormodels.IdsecSIADoctorTarget{Hostname: "target.example.com"}
	tasks := svc.certificateCheckTasks(target, []string{"10.0.0.9"}, "dc.example.com", nil, poolWith(ca), nil)
	require.Len(t, tasks, 1)

	markers := tasks[0]()
	require.Len(t, markers, 1, "LDAPS verdict lands only on the DC host in target mode")
	require.Equal(t, "dc.example.com", markers[0].Host)
	require.Equal(t, ldapsPort, markers[0].Port)
}

func TestCertListUnavailableRows(t *testing.T) {
	svc := newTestService()
	svc.certProbes = map[string]certProbe{
		doctormodels.ProtocolRDP:   &fakeProbe{proto: doctormodels.ProtocolRDP},
		doctormodels.ProtocolMySQL: &fakeProbe{proto: doctormodels.ProtocolMySQL},
	}

	target := doctormodels.IdsecSIADoctorTarget{Hostname: "target.example.com"}
	rows := svc.certListUnavailableRows(target, nil, "", nil, context.DeadlineExceeded)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.Equal(t, doctormodels.FlowTLSCertificate, r.Flow)
		require.Equal(t, doctormodels.CertStatusUnverified, r.CertStatus)
		require.NotEmpty(t, r.Warning)
	}
}
