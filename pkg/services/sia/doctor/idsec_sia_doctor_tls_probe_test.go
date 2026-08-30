package doctor

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

func TestNewCertProbes_Registry(t *testing.T) {
	probes := newCertProbes()

	// SSH is intentionally absent (host keys, not X.509).
	_, hasSSH := probes[doctormodels.ProtocolSSH]
	require.False(t, hasSSH, "ssh must not have a cert probe")

	// Every registered probe reports the protocol it is keyed under.
	for proto, probe := range probes {
		require.Equal(t, proto, probe.Protocol(), "probe for %q reports mismatched protocol", proto)
	}

	// The TLS-capable protocols must all be present.
	for _, proto := range []string{
		doctormodels.ProtocolK8S, doctormodels.ProtocolMongoDB, doctormodels.ProtocolOracle,
		doctormodels.ProtocolDB2, doctormodels.ProtocolPostgreSQL, doctormodels.ProtocolMySQL,
		doctormodels.ProtocolMariaDB, doctormodels.ProtocolRDP, doctormodels.ProtocolMSSQL,
		protocolWinRMHTTPS, protocolLDAPS,
	} {
		_, ok := probes[proto]
		require.True(t, ok, "missing probe for %q", proto)
	}
}

func TestDirectTLSProbe_ResolvesServerCertificate(t *testing.T) {
	ca, caKey := newCA(t)
	cert, leaf := newLeaf(t, ca, caKey, "direct.example.com")
	host, port := startTLSServer(t, serverTLSConfig(cert, tls.NoClientCert))

	probe := &directTLSProbe{protocol: doctormodels.ProtocolK8S}
	res, err := probe.Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, res.TLSOffered)
	require.NotNil(t, res.Leaf)
	require.Equal(t, leaf.SerialNumber, res.Leaf.SerialNumber)
	require.Equal(t, "direct.example.com", res.Leaf.Subject.CommonName)
}

// TestDirectTLSProbe_MutualTLSStillCapturesCertificate covers the mTLS fix: a
// server that demands a client certificate aborts the handshake, but the probe
// must still resolve the server certificate captured mid-handshake.
func TestDirectTLSProbe_MutualTLSStillCapturesCertificate(t *testing.T) {
	ca, caKey := newCA(t)
	cert, leaf := newLeaf(t, ca, caKey, "mtls.example.com")
	host, port := startTLSServer(t, serverTLSConfig(cert, tls.RequireAnyClientCert))

	probe := &directTLSProbe{protocol: doctormodels.ProtocolOracle}
	res, err := probe.Probe(context.Background(), host, port, 5)
	require.NoError(t, err, "server cert must be resolved even though the mTLS handshake fails")
	require.NotNil(t, res)
	require.True(t, res.TLSOffered)
	require.NotNil(t, res.Leaf)
	require.Equal(t, leaf.SerialNumber, res.Leaf.SerialNumber)
}

func TestDirectTLSProbe_DialError(t *testing.T) {
	probe := &directTLSProbe{protocol: doctormodels.ProtocolK8S}
	// Port 1 on loopback is (essentially) always closed.
	_, err := probe.Probe(context.Background(), "127.0.0.1", 1, 1)
	require.Error(t, err)
}

func TestPostgresProbe_STARTTLS(t *testing.T) {
	ca, caKey := newCA(t)
	cert, _ := newLeaf(t, ca, caKey, "pg.example.com")
	serverCfg := serverTLSConfig(cert, tls.NoClientCert)

	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		if _, err := io.ReadFull(c, make([]byte, 8)); err != nil { // SSLRequest
			return
		}
		if _, err := c.Write([]byte{'S'}); err != nil { // SSL supported
			return
		}
		tc := tls.Server(c, serverCfg)
		_ = tc.Handshake()
		_ = tc.Close()
	})

	res, err := (&postgresProbe{}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.True(t, res.TLSOffered)
	require.NotNil(t, res.Leaf)
}

func TestPostgresProbe_NoTLS(t *testing.T) {
	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		if _, err := io.ReadFull(c, make([]byte, 8)); err != nil {
			return
		}
		_, _ = c.Write([]byte{'N'}) // SSL not supported
	})

	res, err := (&postgresProbe{}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.False(t, res.TLSOffered)
}

func TestMySQLProbe_STARTTLS(t *testing.T) {
	ca, caKey := newCA(t)
	cert, _ := newLeaf(t, ca, caKey, "mysql.example.com")
	serverCfg := serverTLSConfig(cert, tls.NoClientCert)

	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		// Server greeting: 4-byte header (payloadLen=1, seq=0) + payload byte.
		if _, err := c.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x0a}); err != nil {
			return
		}
		// Read the client SSLRequest packet: 4-byte header + 32-byte body.
		if _, err := io.ReadFull(c, make([]byte, 4+32)); err != nil {
			return
		}
		tc := tls.Server(c, serverCfg)
		_ = tc.Handshake()
		_ = tc.Close()
	})

	res, err := (&mysqlProbe{protocol: doctormodels.ProtocolMySQL}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.True(t, res.TLSOffered)
	require.NotNil(t, res.Leaf)
}

func TestMySQLProbe_ErrorPacket(t *testing.T) {
	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		// Greeting whose first payload byte is 0xff (error packet).
		_, _ = c.Write([]byte{0x01, 0x00, 0x00, 0x00, 0xff})
	})

	_, err := (&mysqlProbe{protocol: doctormodels.ProtocolMySQL}).Probe(context.Background(), host, port, 5)
	require.Error(t, err)
}

func TestRDPProbe_NegotiatesSSL(t *testing.T) {
	ca, caKey := newCA(t)
	cert, _ := newLeaf(t, ca, caKey, "rdp.example.com")
	serverCfg := serverTLSConfig(cert, tls.NoClientCert)

	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		hdr := make([]byte, tpktHeaderLen)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		total := int(binary.BigEndian.Uint16(hdr[2:4]))
		if _, err := io.ReadFull(c, make([]byte, total-tpktHeaderLen)); err != nil {
			return
		}
		// X.224 Connection Confirm carrying an RDP_NEG_RSP selecting PROTOCOL_SSL.
		rest := []byte{
			14, x224ConnectionCC, 0, 0, 0, 0, 0, // LI, CC, DST-REF, SRC-REF, CLASS
			rdpNegRspType, 0x00, 0x08, 0x00, // type, flags, length(8, LE)
			rdpProtocolSSL, 0x00, 0x00, 0x00, // selectedProtocol (LE)
		}
		resp := []byte{tpktVersion, 0x00, 0x00, byte(tpktHeaderLen + len(rest))}
		resp = append(resp, rest...)
		if _, err := c.Write(resp); err != nil {
			return
		}
		tc := tls.Server(c, serverCfg)
		_ = tc.Handshake()
		_ = tc.Close()
	})

	res, err := (&rdpProbe{}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.True(t, res.TLSOffered)
	require.NotNil(t, res.Leaf)
}

func TestRDPProbe_NegotiationDeclined(t *testing.T) {
	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		hdr := make([]byte, tpktHeaderLen)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		total := int(binary.BigEndian.Uint16(hdr[2:4]))
		if _, err := io.ReadFull(c, make([]byte, total-tpktHeaderLen)); err != nil {
			return
		}
		// A short confirm with no negotiation response → probe reports no TLS.
		rest := []byte{6, x224ConnectionCC, 0, 0, 0, 0, 0}
		resp := []byte{tpktVersion, 0x00, 0x00, byte(tpktHeaderLen + len(rest))}
		resp = append(resp, rest...)
		_, _ = c.Write(resp)
	})

	res, err := (&rdpProbe{}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.False(t, res.TLSOffered)
}

func TestMSSQLProbe_EncryptionNotSupported(t *testing.T) {
	host, port := startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		if _, err := readTDSPacket(c); err != nil { // client PRELOGIN
			return
		}
		// PRELOGIN response with a single ENCRYPTION option = ENCRYPT_NOT_SUP.
		body := []byte{
			tdsOptEncryption, 0x00, 0x06, 0x00, 0x01, // token: type, offset(6), length(1)
			tdsOptTerminator,
			tdsEncryptNotSup,
		}
		pkt := make([]byte, tdsHeaderLen)
		pkt[0] = tdsTypePrelogin
		pkt[1] = tdsStatusEOM
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(body)+tdsHeaderLen))
		pkt = append(pkt, body...)
		_, _ = c.Write(pkt)
	})

	res, err := (&mssqlProbe{}).Probe(context.Background(), host, port, 5)
	require.NoError(t, err)
	require.False(t, res.TLSOffered)
}

func TestBuildRDPConnectionRequest(t *testing.T) {
	pkt := buildRDPConnectionRequest()
	require.Equal(t, byte(tpktVersion), pkt[0])
	require.Equal(t, len(pkt), int(binary.BigEndian.Uint16(pkt[2:4])), "TPKT length must match packet size")

	// The negotiation request must advertise SSL | HYBRID (CredSSP).
	neg := pkt[len(pkt)-rdpNegotiationLen:]
	require.Equal(t, byte(rdpNegReqType), neg[0])
	requested := binary.LittleEndian.Uint32(neg[4:8])
	require.Equal(t, uint32(rdpProtocolSSL|rdpProtocolHybrid), requested)
}

func TestBuildAndParseTDSPrelogin(t *testing.T) {
	pkt := buildTDSPrelogin()
	require.Equal(t, byte(tdsTypePrelogin), pkt[0])
	require.Equal(t, byte(tdsStatusEOM), pkt[1])
	require.Equal(t, len(pkt), int(binary.BigEndian.Uint16(pkt[2:4])))

	enc, ok := parsePreloginEncryption(pkt[tdsHeaderLen:])
	require.True(t, ok)
	require.Equal(t, byte(0x01), enc, "prelogin must advertise ENCRYPT_ON")
}

func TestProbeDeadline(t *testing.T) {
	// Without a ctx deadline, now+timeout is used.
	d := probeDeadline(context.Background(), 5)
	require.WithinDuration(t, time.Now().Add(5*time.Second), d, time.Second)

	// A nearer ctx deadline wins over the timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d = probeDeadline(ctx, 3600)
	require.WithinDuration(t, time.Now().Add(time.Second), d, 500*time.Millisecond)
}
