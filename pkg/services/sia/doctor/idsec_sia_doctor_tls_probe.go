package doctor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	doctormodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/models"
)

// protocolWinRMHTTPS and protocolLDAPS are the reachability-row protocol labels
// for the two TLS-capable domain-ephemeral endpoints. They are plain strings
// (not model constants) to match the labels used when their reachability probes
// are emitted.
const (
	protocolWinRMHTTPS = "winrm-https"
	protocolLDAPS      = "ldaps"
	// ldapsPort is the fixed connector→DC LDAPS port used for target checks.
	ldapsPort = 636
)

// pgSSLRequestCode is the magic protocol version in a PostgreSQL SSLRequest.
const pgSSLRequestCode = 80877103

const (
	mysqlClientProtocol41      = 0x00000200
	mysqlClientSSL             = 0x00000800
	mysqlClientSecureConnstate = 0x00008000
	mysqlErrPacket             = 0xff
)

const (
	rdpNegReqType  = 0x01
	rdpNegRspType  = 0x02
	rdpProtocolSSL = 0x00000001
	// rdpProtocolHybrid is CredSSP/NLA. Windows Servers with NLA enabled reject
	// a pure-SSL request, so we advertise both and accept either — in both cases
	// the server completes a standard TLS handshake (presenting its certificate)
	// before any CredSSP exchange, which is all we need to resolve the cert.
	rdpProtocolHybrid = 0x00000002
	x224ConnectionCC  = 0xd0
	tpktVersion       = 0x03
	tpktHeaderLen     = 4
	rdpNegotiationLen = 8
)

const (
	tdsTypePrelogin  = 0x12
	tdsStatusEOM     = 0x01
	tdsHeaderLen     = 8
	tdsOptEncryption = 0x01
	tdsOptVersion    = 0x00
	tdsOptTerminator = 0xff

	tdsEncryptNotSup = 0x02

	tdsMaxPayload = 4096 - tdsHeaderLen
)

// certProbeResult is what a probe resolves from a server.
type certProbeResult struct {
	// Leaf is the server's leaf (end-entity) certificate.
	Leaf *x509.Certificate
	// Intermediates are any additional certificates the server presented,
	// used as intermediates during chain verification.
	Intermediates []*x509.Certificate
	// TLSOffered is false when the endpoint accepted the connection but did not
	// offer TLS (e.g. PostgreSQL / MySQL replied "no SSL").
	TLSOffered bool
	// LatencyMs is the TLS handshake duration in milliseconds.
	LatencyMs int
}

// certProbe resolves the server certificate presented for one protocol.
// Implementations own that protocol's TLS negotiation (direct TLS, STARTTLS,
// RDP X.224 upgrade, or MSSQL/TDS tunnel).
type certProbe interface {
	// Probe dials host:port and negotiates TLS according to the protocol,
	// returning the resolved certificate(s). It returns an error for
	// connection / negotiation / handshake failures; a successful connection to
	// a non-TLS endpoint returns a result with TLSOffered=false and no error.
	Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error)
	// Protocol returns the protocol constant this probe handles.
	Protocol() string
}

type directTLSProbe struct{ protocol string }

type postgresProbe struct{}

type mysqlProbe struct{ protocol string }

type rdpProbe struct{}

type mssqlProbe struct{}

// tdsPreloginConn wraps a raw connection so the TLS handshake records are framed
// inside TDS pre-login packets (type 0x12), matching SQL Server's pre-login TLS
// tunnel. It is used only for the handshake — this probe never sends TLS
// application data.
type tdsPreloginConn struct {
	net.Conn
	readBuf bytes.Buffer
}

// newCertProbes returns the protocol -> probe registry. SSH is intentionally
// absent (SSH uses host keys, not X.509). The key set is the single source of
// truth for which protocols receive a certificate check.
func newCertProbes() map[string]certProbe {
	return map[string]certProbe{
		doctormodels.ProtocolK8S:        &directTLSProbe{protocol: doctormodels.ProtocolK8S},
		doctormodels.ProtocolMongoDB:    &directTLSProbe{protocol: doctormodels.ProtocolMongoDB},
		doctormodels.ProtocolOracle:     &directTLSProbe{protocol: doctormodels.ProtocolOracle},
		doctormodels.ProtocolDB2:        &directTLSProbe{protocol: doctormodels.ProtocolDB2},
		doctormodels.ProtocolPostgreSQL: &postgresProbe{},
		doctormodels.ProtocolMySQL:      &mysqlProbe{protocol: doctormodels.ProtocolMySQL},
		doctormodels.ProtocolMariaDB:    &mysqlProbe{protocol: doctormodels.ProtocolMariaDB},
		doctormodels.ProtocolRDP:        &rdpProbe{},
		doctormodels.ProtocolMSSQL:      &mssqlProbe{},
		// WinRM HTTPS and LDAPS are plain TLS on their respective ports, so the
		// direct-TLS probe resolves their server certificates as-is.
		protocolWinRMHTTPS: &directTLSProbe{protocol: protocolWinRMHTTPS},
		protocolLDAPS:      &directTLSProbe{protocol: protocolLDAPS},
	}
}

// dialTCP opens a TCP connection bounded by ctx and timeoutSec.
func dialTCP(ctx context.Context, host string, port, timeoutSec int) (net.Conn, error) {
	d := net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// probeDeadline returns the earlier of ctx's deadline and now+timeoutSec.
func probeDeadline(ctx context.Context, timeoutSec int) time.Time {
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

// completeTLSHandshake performs a client TLS handshake over conn and returns the
// resolved certificate(s). InsecureSkipVerify is set because we only resolve the
// certificate here; trust is verified separately against the tenant pool.
//
// The server's certificate chain is captured via VerifyPeerCertificate, which
// Go invokes with the presented certs during the handshake — before it
// completes — even when InsecureSkipVerify is set. This lets the probe resolve
// the server certificate even for endpoints that require a client certificate
// (mutual TLS), such as the SIA database gateways: the server presents its own
// Let's Encrypt certificate and then aborts with a handshake_failure alert
// because the probe offers no client cert, but by then we have already captured
// what we need.
func completeTLSHandshake(ctx context.Context, conn net.Conn, serverName string, timeoutSec int) (*certProbeResult, error) {
	_ = conn.SetDeadline(probeDeadline(ctx, timeoutSec))
	start := time.Now()

	var presented []*x509.Certificate
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- certificate is resolved here and verified separately against the tenant trust store
		ServerName:         serverName,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if c, err := x509.ParseCertificate(raw); err == nil {
					presented = append(presented, c)
				}
			}
			return nil
		},
	})
	handshakeErr := tlsConn.HandshakeContext(ctx)
	latency := int(time.Since(start).Milliseconds())

	// Prefer the negotiated state; fall back to the certs captured mid-handshake
	// (mutual-TLS endpoints reject us after presenting their own certificate).
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		certs = presented
	}
	if len(certs) == 0 {
		if handshakeErr != nil {
			return nil, handshakeErr
		}
		return nil, fmt.Errorf("server presented no certificates")
	}

	res := &certProbeResult{
		Leaf:       certs[0],
		TLSOffered: true,
		LatencyMs:  latency,
	}
	if len(certs) > 1 {
		res.Intermediates = certs[1:]
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Direct TLS (K8S, MongoDB, Oracle TCPS, DB2)
// ---------------------------------------------------------------------------

func (p *directTLSProbe) Protocol() string { return p.protocol }

func (p *directTLSProbe) Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error) {
	conn, err := dialTCP(ctx, host, port, timeoutSec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return completeTLSHandshake(ctx, conn, host, timeoutSec)
}

// ---------------------------------------------------------------------------
// PostgreSQL STARTTLS
// ---------------------------------------------------------------------------

func (p *postgresProbe) Protocol() string { return doctormodels.ProtocolPostgreSQL }

func (p *postgresProbe) Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error) {
	conn, err := dialTCP(ctx, host, port, timeoutSec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(probeDeadline(ctx, timeoutSec))

	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], pgSSLRequestCode)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read SSLRequest response: %w", err)
	}
	if resp[0] != 'S' {
		return &certProbeResult{TLSOffered: false}, nil
	}
	return completeTLSHandshake(ctx, conn, host, timeoutSec)
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB STARTTLS
// ---------------------------------------------------------------------------

func (p *mysqlProbe) Protocol() string { return p.protocol }

func (p *mysqlProbe) Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error) {
	conn, err := dialTCP(ctx, host, port, timeoutSec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(probeDeadline(ctx, timeoutSec))

	// Read the server's initial handshake packet to learn the sequence id.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("failed to read server greeting header: %w", err)
	}
	payloadLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq := hdr[3]
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("failed to read server greeting: %w", err)
	}
	if payloadLen > 0 && payload[0] == mysqlErrPacket {
		return nil, fmt.Errorf("server rejected connection with an error packet before TLS negotiation")
	}

	// Build the SSLRequest packet (HandshakeResponse41 truncated to 32 bytes).
	capabilities := uint32(mysqlClientProtocol41 | mysqlClientSSL | mysqlClientSecureConnstate)
	body := make([]byte, 32)
	binary.LittleEndian.PutUint32(body[0:4], capabilities)
	binary.LittleEndian.PutUint32(body[4:8], 1<<24-1) // max packet size
	body[8] = 0x21                                    // charset utf8_general_ci
	// body[9:32] reserved (already zero)

	pkt := make([]byte, 0, 4+len(body))
	pkt = append(pkt, byte(len(body)), byte(len(body)>>8), byte(len(body)>>16), seq+1)
	pkt = append(pkt, body...)
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("failed to send SSLRequest: %w", err)
	}
	return completeTLSHandshake(ctx, conn, host, timeoutSec)
}

// ---------------------------------------------------------------------------
// RDP (X.224 Connection Request → TLS upgrade)
// ---------------------------------------------------------------------------

func (p *rdpProbe) Protocol() string { return doctormodels.ProtocolRDP }

func (p *rdpProbe) Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error) {
	conn, err := dialTCP(ctx, host, port, timeoutSec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(probeDeadline(ctx, timeoutSec))

	if _, err := conn.Write(buildRDPConnectionRequest()); err != nil {
		return nil, fmt.Errorf("failed to send X.224 connection request: %w", err)
	}

	tpkt := make([]byte, tpktHeaderLen)
	if _, err := io.ReadFull(conn, tpkt); err != nil {
		return nil, fmt.Errorf("failed to read X.224 connection confirm header: %w", err)
	}
	totalLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if totalLen < tpktHeaderLen {
		return nil, fmt.Errorf("invalid TPKT length %d", totalLen)
	}
	rest := make([]byte, totalLen-tpktHeaderLen)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, fmt.Errorf("failed to read X.224 connection confirm: %w", err)
	}

	// rest: LI(1) CC(1) DST-REF(2) SRC-REF(2) CLASS(1) then optional negotiation response.
	const negOffset = 7
	if len(rest) < negOffset+rdpNegotiationLen || rest[1] != x224ConnectionCC {
		// No negotiation response → server did not select an enhanced protocol.
		return &certProbeResult{TLSOffered: false}, nil
	}
	if rest[negOffset] != rdpNegRspType {
		return &certProbeResult{TLSOffered: false}, nil
	}
	selected := binary.LittleEndian.Uint32(rest[negOffset+4 : negOffset+8])
	if selected&(rdpProtocolSSL|rdpProtocolHybrid) == 0 {
		return &certProbeResult{TLSOffered: false}, nil
	}
	return completeTLSHandshake(ctx, conn, host, timeoutSec)
}

// buildRDPConnectionRequest builds a TPKT-framed X.224 Connection Request that
// carries an RDP_NEG_REQ requesting PROTOCOL_SSL.
func buildRDPConnectionRequest() []byte {
	neg := make([]byte, rdpNegotiationLen)
	neg[0] = rdpNegReqType
	neg[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(neg[2:4], rdpNegotiationLen)
	binary.LittleEndian.PutUint32(neg[4:8], rdpProtocolSSL|rdpProtocolHybrid)

	// X.224 Connection Request fixed part (after the LI byte): CR CDT, DST-REF,
	// SRC-REF, class option.
	x224 := []byte{0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	li := byte(len(x224) + len(neg))

	total := tpktHeaderLen + 1 + len(x224) + len(neg)
	pkt := make([]byte, 0, total)
	pkt = append(pkt, tpktVersion, 0x00, byte(total>>8), byte(total))
	pkt = append(pkt, li)
	pkt = append(pkt, x224...)
	pkt = append(pkt, neg...)
	return pkt
}

// ---------------------------------------------------------------------------
// MSSQL (TDS PRELOGIN → TLS handshake tunneled inside TDS pre-login packets)
// ---------------------------------------------------------------------------

func (p *mssqlProbe) Protocol() string { return doctormodels.ProtocolMSSQL }

func (p *mssqlProbe) Probe(ctx context.Context, host string, port, timeoutSec int) (*certProbeResult, error) {
	conn, err := dialTCP(ctx, host, port, timeoutSec)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(probeDeadline(ctx, timeoutSec))

	if _, err := conn.Write(buildTDSPrelogin()); err != nil {
		return nil, fmt.Errorf("failed to send TDS pre-login: %w", err)
	}
	body, err := readTDSPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read TDS pre-login response: %w", err)
	}
	if enc, ok := parsePreloginEncryption(body); ok && enc == tdsEncryptNotSup {
		return &certProbeResult{TLSOffered: false}, nil
	}

	// TLS handshake is tunneled inside TDS pre-login packets.
	tdsConn := &tdsPreloginConn{Conn: conn}
	return completeTLSHandshake(ctx, tdsConn, host, timeoutSec)
}

// buildTDSPrelogin builds a TDS PRELOGIN packet advertising ENCRYPT_ON, which
// prompts SQL Server to begin the pre-login TLS handshake.
func buildTDSPrelogin() []byte {
	versionData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	encData := []byte{0x01} // ENCRYPT_ON

	tokenAreaLen := 2*5 + 1 // VERSION + ENCRYPTION tokens + terminator
	verOffset := tokenAreaLen
	encOffset := verOffset + len(versionData)

	payload := make([]byte, 0, tokenAreaLen+len(versionData)+len(encData))
	payload = append(payload, tdsOptVersion)
	payload = appendUint16BE(payload, uint16(verOffset))
	payload = appendUint16BE(payload, uint16(len(versionData)))
	payload = append(payload, tdsOptEncryption)
	payload = appendUint16BE(payload, uint16(encOffset))
	payload = appendUint16BE(payload, uint16(len(encData)))
	payload = append(payload, tdsOptTerminator)
	payload = append(payload, versionData...)
	payload = append(payload, encData...)

	pkt := make([]byte, tdsHeaderLen)
	pkt[0] = tdsTypePrelogin
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(payload)+tdsHeaderLen))
	return append(pkt, payload...)
}

// parsePreloginEncryption walks the pre-login option tokens and returns the
// server's ENCRYPTION byte.
func parsePreloginEncryption(body []byte) (byte, bool) {
	for i := 0; i+5 <= len(body); i += 5 {
		if body[i] == tdsOptTerminator {
			break
		}
		offset := binary.BigEndian.Uint16(body[i+1 : i+3])
		length := binary.BigEndian.Uint16(body[i+3 : i+5])
		if body[i] == tdsOptEncryption && length >= 1 && int(offset)+int(length) <= len(body) {
			return body[offset], true
		}
	}
	return 0, false
}

// readTDSPacket reads one full TDS packet from conn and returns its payload.
func readTDSPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, tdsHeaderLen)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < tdsHeaderLen {
		return nil, fmt.Errorf("invalid TDS packet length %d", length)
	}
	body := make([]byte, length-tdsHeaderLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (c *tdsPreloginConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > tdsMaxPayload {
			chunk = p[:tdsMaxPayload]
		}
		pkt := make([]byte, tdsHeaderLen, tdsHeaderLen+len(chunk))
		pkt[0] = tdsTypePrelogin
		pkt[1] = tdsStatusEOM
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(chunk)+tdsHeaderLen))
		pkt = append(pkt, chunk...)
		if _, err := c.Conn.Write(pkt); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *tdsPreloginConn) Read(p []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		body, err := readTDSPacket(c.Conn)
		if err != nil {
			return 0, err
		}
		c.readBuf.Write(body)
	}
	return c.readBuf.Read(p)
}

// appendUint16BE appends v to b in big-endian order.
func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
