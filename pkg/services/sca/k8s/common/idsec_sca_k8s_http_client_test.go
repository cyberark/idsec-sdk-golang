package common

import (
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// isolateNetworkConfig clears SDK network settings that could leak in from the
// environment and restores the defaults after the test.
func isolateNetworkConfig(t *testing.T) {
	t.Helper()
	t.Setenv(config.IdsecProxyAddressEnvVar, "")
	t.Setenv(config.IdsecDisableCertificateVerificationEnvVar, "")
	t.Setenv(config.IdsecExtraTrustedCACertsBundlePathEnvVar, "")
	t.Cleanup(func() {
		config.SetProxyAddress("")
		config.SetTrustedCertificate("")
		config.EnableCertificateVerification()
	})
}

func TestK8sHTTPClient_TrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	srvCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))

	cases := []struct {
		name          string
		trusted       string
		disableVerify bool
		disableEnv    bool
		wantErr       bool
	}{
		{name: "configured CA is trusted", trusted: srvCertPEM},
		{name: "unknown CA is rejected", wantErr: true},
		{name: "verification toggle cannot bypass an unknown CA", disableVerify: true, wantErr: true},
		{name: "verification env var cannot bypass an unknown CA", disableEnv: true, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			isolateNetworkConfig(t)
			config.SetTrustedCertificate(c.trusted)
			if c.disableVerify {
				config.DisableCertificateVerification()
			}
			if c.disableEnv {
				t.Setenv(config.IdsecDisableCertificateVerificationEnvVar, "true")
			}

			resp, err := K8sHTTPClient(5 * time.Second).Get(srv.URL)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("Get() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestK8sHTTPClient_NetworkPolicy(t *testing.T) {
	isolateNetworkConfig(t)
	config.SetProxyAddress("http://proxy.example.test:8080")

	client := K8sHTTPClient(7 * time.Second)
	transport := client.Transport.(*http.Transport)

	req, _ := http.NewRequest(http.MethodGet, "https://oidc.us-east-1.amazonaws.com/token", nil)
	proxyURL, err := transport.Proxy(req)
	if err != nil || proxyURL == nil || proxyURL.Host != "proxy.example.test:8080" {
		t.Errorf("proxy = %v, err = %v; want proxy.example.test:8080", proxyURL, err)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", client.Timeout)
	}
}
