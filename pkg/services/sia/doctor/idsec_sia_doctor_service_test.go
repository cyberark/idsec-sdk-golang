package doctor

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

func TestResolveModes(t *testing.T) {
	svc := newTestService()

	t.Run("auto_defaults_client_and_connector", func(t *testing.T) {
		got := svc.resolveModes(&doctormodels.IdsecSIADoctorCheck{})
		require.Equal(t, []string{modeClient, modeConnector}, got)
	})

	t.Run("auto_adds_target_and_dc_when_inputs_present", func(t *testing.T) {
		got := svc.resolveModes(&doctormodels.IdsecSIADoctorCheck{
			Targets:           []doctormodels.IdsecSIADoctorTarget{{Hostname: "t"}},
			DomainControllers: []doctormodels.IdsecSIADoctorTarget{{Hostname: "dc"}},
		})
		require.Equal(t, []string{modeClient, modeConnector, modeTarget, modeDomainController}, got)
	})

	t.Run("explicit_modes_with_dc_alias_and_ordering", func(t *testing.T) {
		got := svc.resolveModes(&doctormodels.IdsecSIADoctorCheck{
			Modes: []string{"dc", "target", "client"},
		})
		// Canonical order regardless of input order; "dc" maps to domain-controller.
		require.Equal(t, []string{modeClient, modeTarget, modeDomainController}, got)
	})

	t.Run("explicit_modes_dedupe_and_ignore_unknown", func(t *testing.T) {
		got := svc.resolveModes(&doctormodels.IdsecSIADoctorCheck{
			Modes: []string{"client", "client", "bogus"},
		})
		require.Equal(t, []string{modeClient}, got)
	})
}

func TestMakeProtocolSet(t *testing.T) {
	svc := newTestService()
	require.Nil(t, svc.makeProtocolSet(nil))
	require.Nil(t, svc.makeProtocolSet([]string{}))

	set := svc.makeProtocolSet([]string{"RDP", "MySQL"})
	require.True(t, set["rdp"])
	require.True(t, set["mysql"])
	require.False(t, set["ssh"])
}

func TestApplyDefaults(t *testing.T) {
	svc := newTestService()
	target := doctormodels.IdsecSIADoctorTarget{RDPPort: 4000} // explicit override kept
	svc.applyDefaults(&target)

	require.Equal(t, 4000, target.RDPPort)
	require.Equal(t, defaultSSHPort, target.SSHPort)
	require.Equal(t, defaultMongoDBPort, target.MongoDBPort)
	require.Equal(t, defaultK8SPort, target.K8SPort)
}

func TestBuildReport_Summary(t *testing.T) {
	checks := []doctormodels.IdsecSIADoctorCheckResult{
		{Status: doctormodels.CheckStatusPass},
		{Status: doctormodels.CheckStatusFail},
		{Status: doctormodels.CheckStatusNA},
		{Status: doctormodels.CheckStatusSkipped},
		{Status: doctormodels.CheckStatusPass, Warning: "heads up"},
	}
	report := newTestService().buildReport("target", checks)

	require.Equal(t, "target", report.Mode)
	require.Equal(t, 5, report.Summary.Total)
	require.Equal(t, 2, report.Summary.Passed)
	require.Equal(t, 1, report.Summary.Failed)
	require.Equal(t, 1, report.Summary.NA)
	require.Equal(t, 1, report.Summary.Skipped)
	require.Equal(t, 1, report.Summary.Warnings)
}

func TestDedupeResults(t *testing.T) {
	checks := []doctormodels.IdsecSIADoctorCheckResult{
		{Protocol: "rdp", Flow: "gw", Host: "h", Port: 443, CheckedFrom: "c1", Status: doctormodels.CheckStatusFail},
		// Same key, higher-ranked status wins (pass > fail).
		{Protocol: "rdp", Flow: "gw", Host: "h", Port: 443, CheckedFrom: "c1", Status: doctormodels.CheckStatusPass},
		// Different CheckedFrom → kept as its own row.
		{Protocol: "rdp", Flow: "gw", Host: "h", Port: 443, CheckedFrom: "c2", Status: doctormodels.CheckStatusFail},
	}
	out := newTestService().dedupeResults(checks)
	require.Len(t, out, 2)
	require.Equal(t, doctormodels.CheckStatusPass, out[0].Status)
	require.Equal(t, "c1", out[0].CheckedFrom)
	require.Equal(t, "c2", out[1].CheckedFrom)
}

func TestSummarizeReach(t *testing.T) {
	svc := newTestService()
	reached, latency, desc := svc.summarizeReach([]doctormodels.IdsecSIADoctorCheckResult{
		{Status: doctormodels.CheckStatusFail, Description: "first fail"},
		{Status: doctormodels.CheckStatusPass, LatencyMs: 42, Description: "reachable"},
	})
	require.True(t, reached)
	require.Equal(t, 42, latency)
	require.Equal(t, "reachable", desc)

	reached, _, desc = svc.summarizeReach([]doctormodels.IdsecSIADoctorCheckResult{
		{Status: doctormodels.CheckStatusFail, Description: "boom"},
	})
	require.False(t, reached)
	require.Equal(t, "boom", desc)
}

func TestIsUnroutableErr(t *testing.T) {
	svc := newTestService()
	require.True(t, svc.isUnroutableErr("dial tcp: lookup foo: no such host"))
	require.True(t, svc.isUnroutableErr("connect: no route to host"))
	require.True(t, svc.isUnroutableErr("network is unreachable"))
	// A plain timeout is NOT unroutable (a single filtered port must not fail the host).
	require.False(t, svc.isUnroutableErr("i/o timeout"))
	require.False(t, svc.isUnroutableErr("context deadline exceeded"))
}

func TestFilterNA(t *testing.T) {
	out := newTestService().filterNA([]doctormodels.IdsecSIADoctorCheckResult{
		{Protocol: "a", Status: doctormodels.CheckStatusPass},
		{Protocol: "b", Status: doctormodels.CheckStatusNA},
		{Protocol: "c", Status: doctormodels.CheckStatusFail},
	})
	require.Len(t, out, 2)
	for _, c := range out {
		require.NotEqual(t, doctormodels.CheckStatusNA, c.Status)
	}
}

func TestStampDuration(t *testing.T) {
	svc := newTestService()
	// nil-safe: must not panic.
	svc.stampDuration(nil, time.Now())
	var nilReport *doctormodels.IdsecSIADoctorReport
	svc.stampDuration(&nilReport, time.Now())

	report := &doctormodels.IdsecSIADoctorReport{}
	svc.stampDuration(&report, time.Now().Add(-25*time.Millisecond))
	require.GreaterOrEqual(t, report.DurationMs, int64(20))
}

func TestRunParallel_CollectsAllResults(t *testing.T) {
	svc := newTestService()
	var ran int32
	var tasks []checkFn
	for i := 0; i < 10; i++ {
		i := i
		tasks = append(tasks, func() []doctormodels.IdsecSIADoctorCheckResult {
			atomic.AddInt32(&ran, 1)
			return []doctormodels.IdsecSIADoctorCheckResult{{Protocol: "p", Port: i}}
		})
	}
	out := svc.runParallel(context.Background(), 4, tasks)
	require.Equal(t, int32(10), atomic.LoadInt32(&ran))
	require.Len(t, out, 10)

	ports := make([]int, 0, len(out))
	for _, c := range out {
		ports = append(ports, c.Port)
	}
	sort.Ints(ports)
	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, ports)
}

func TestLocalTCPDial(t *testing.T) {
	svc := newTestService()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	openPort, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	pass := svc.localTCPDial("k8s", doctormodels.FlowGW, "127.0.0.1", openPort, 2)
	require.Equal(t, doctormodels.CheckStatusPass, pass.Status)
	require.Equal(t, "reachable", pass.Description)
	require.Equal(t, "local", pass.CheckedFrom)

	fail := svc.localTCPDial("k8s", doctormodels.FlowGW, "127.0.0.1", 1, 1)
	require.Equal(t, doctormodels.CheckStatusFail, fail.Status)
}
func TestCheckRequestProjections(t *testing.T) {
	req := &doctormodels.IdsecSIADoctorCheck{
		Clients:                 []doctormodels.IdsecSIADoctorTarget{{Hostname: "client"}},
		Targets:                 []doctormodels.IdsecSIADoctorTarget{{Hostname: "target"}},
		DomainControllers:       []doctormodels.IdsecSIADoctorTarget{{Hostname: "dc"}},
		ConnectorIDs:            []string{"c-1"},
		LocalConnector:          true,
		Protocols:               []string{"rdp"},
		ShowAll:                 true,
		ConnectTimeout:          7,
		DisableCertificateCheck: true,
		ConcurrencyLimit:        9,
		TimeoutSec:              99,
		BatchReachability:       true,
	}

	client := req.ClientRequest()
	require.Equal(t, req.Clients, client.Clients)
	require.Equal(t, req.Protocols, client.Protocols)
	require.Equal(t, 7, client.ConnectTimeout)
	require.True(t, client.DisableCertificateCheck)

	target := req.TargetRequest()
	require.Equal(t, req.Targets, target.Targets)
	require.Equal(t, req.Protocols, target.Protocols)
	require.Equal(t, req.ConnectorIDs, target.ConnectorIDs)
	require.True(t, target.ShowAll)
	require.Equal(t, 9, target.ConcurrencyLimit)
	require.Equal(t, 99, target.TimeoutSec)
	require.True(t, target.DisableCertificateCheck)
	require.True(t, target.BatchReachability)

	dc := req.DomainControllerRequest()
	require.Equal(t, req.DomainControllers, dc.DomainControllers)
	require.Equal(t, req.ConnectorIDs, dc.ConnectorIDs)
	require.True(t, dc.DisableCertificateCheck)

	connector := req.ConnectorRequest()
	require.True(t, connector.Local)
	require.Equal(t, req.ConnectorIDs, connector.ConnectorIDs)
	require.Equal(t, 99, connector.TimeoutSec)
	require.True(t, connector.BatchReachability)
	// Target reachability is intentionally left to target mode.
	require.Empty(t, connector.Targets)
}
