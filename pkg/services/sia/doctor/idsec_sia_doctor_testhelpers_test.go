package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// newTestService builds a doctor service wired with just the pieces the unit
// tests exercise: a logger and the real cert-probe registry. The ISP / access /
// certificates dependencies are left nil — the tested helpers never touch them.
func newTestService() *IdsecSIADoctorService {
	return &IdsecSIADoctorService{
		IdsecBaseService: &services.IdsecBaseService{Logger: common.GlobalLogger},
		certProbes:       newCertProbes(),
	}
}

// --- Certificate fixtures ---------------------------------------------------

// newCA returns a fresh self-signed CA certificate and its signing key.
func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "IDSEC Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return ca, key
}

// newLeafValidity mints a leaf certificate signed by ca, valid over the given
// window, usable as a TLS server certificate for 127.0.0.1 / cn.
func newLeafValidity(
	t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, notBefore, notAfter time.Time,
) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// newLeaf mints a currently-valid leaf certificate signed by ca.
func newLeaf(
	t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string,
) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	return newLeafValidity(t, ca, caKey, cn, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// poolWith returns a cert pool containing the given certificates.
func poolWith(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// --- Test servers -----------------------------------------------------------

// startRawServer listens on an ephemeral loopback port and hands every accepted
// connection to handle. The listener is closed at test end.
func startRawServer(t *testing.T, handle func(net.Conn)) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(c)
		}
	}()
	h, p, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err = strconv.Atoi(p)
	require.NoError(t, err)
	return h, port
}

// startTLSServer serves a plain (direct) TLS endpoint using cfg.
func startTLSServer(t *testing.T, cfg *tls.Config) (host string, port int) {
	t.Helper()
	return startRawServer(t, func(c net.Conn) {
		defer func() { _ = c.Close() }()
		tc := tls.Server(c, cfg)
		_ = tc.Handshake()
		_ = tc.Close()
	})
}

// serverTLSConfig builds a server TLS config presenting cert with the given
// client-auth policy.
func serverTLSConfig(cert tls.Certificate, clientAuth tls.ClientAuthType) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
	}
}

// --- Fake probe -------------------------------------------------------------

// fakeProbe is a certProbe stub returning a fixed result, so cert-verdict logic
// can be tested without any network I/O.
type fakeProbe struct {
	proto string
	res   *certProbeResult
	err   error
}

func (f *fakeProbe) Protocol() string { return f.proto }

func (f *fakeProbe) Probe(_ context.Context, _ string, _, _ int) (*certProbeResult, error) {
	return f.res, f.err
}
