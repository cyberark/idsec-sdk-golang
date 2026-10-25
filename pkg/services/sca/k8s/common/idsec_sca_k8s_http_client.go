// Package common holds helpers shared by the SCA Kubernetes flows.
//
// K8sHTTPClient is the HTTP client for calls from those flows to third-party
// endpoints (for example AWS IAM Identity Center). It applies the SDK's proxy,
// trusted CA and TLS floor settings but always verifies certificates, and it
// deliberately carries no telemetry headers, cookies or request logging, so
// credentials in third-party requests cannot leak and stdout stays clean for the
// kubectl exec credential plugin. Calls to CyberArk services must keep using the
// SDK service clients instead.
package common

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// K8sHTTPTransport returns a transport that follows the SDK network policy.
//
// It mirrors the transport built by common.NewIdsecClient; keep the two aligned.
// The one intended difference: the SDK-wide "disable certificate verification"
// toggle is ignored, because these requests carry cloud credentials. Trust a
// TLS-inspecting proxy through the trusted certificate or extra CA bundle instead.
// Settings are read when called, so build it after SDK network settings are configured.
func K8sHTTPTransport() *http.Transport {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caCert := config.TrustedCertificate(); caCert != "" {
		rootCAs.AppendCertsFromPEM([]byte(caCert))
	}
	if bundle := readExtraTrustedCABundle(); bundle != nil {
		rootCAs.AppendCertsFromPEM(bundle)
	}
	return &http.Transport{
		Proxy: config.ConfigureProxy,
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		},
	}
}

// K8sHTTPClient returns an HTTP client using K8sHTTPTransport and the given timeout.
// Callers that build one per operation should call CloseIdleConnections when done,
// because the transport keeps idle keep-alive connections open indefinitely.
func K8sHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: K8sHTTPTransport(), Timeout: timeout}
}

// readExtraTrustedCABundle returns the configured extra CA bundle, or nil when it is
// unset or unreadable, matching how the shared SDK client treats it.
func readExtraTrustedCABundle() []byte {
	path := config.ExtraTrustedCACertsBundlePath()
	if path == "" {
		return nil
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil
	}
	return data
}
