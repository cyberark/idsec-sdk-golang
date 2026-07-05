package k8s

import (
	"fmt"
	"strings"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	proxyExecCredAPI           = "client.authentication.k8s.io/v1beta1"
	proxyExecCredRefreshBuffer = 60 * time.Second
)

// parseDpaSsoExpiresAt parses metadata.expires_at from a DPA SSO acquire response.
func parseDpaSsoExpiresAt(meta *k8smodels.IdsecSCAK8sDpaSsoAcquireMetadata) (time.Time, error) {
	if meta == nil {
		return time.Time{}, fmt.Errorf("metadata is missing")
	}
	raw := strings.TrimSpace(meta.ExpiresAt)
	if raw == "" {
		return time.Time{}, fmt.Errorf("metadata.expires_at is empty")
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	}
	var lastErr error
	for _, layout := range layouts {
		t, err := time.Parse(layout, raw)
		if err == nil {
			return t.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, fmt.Errorf("failed to parse metadata.expires_at %q: %w", raw, lastErr)
}

// BuildProxyExecCredential builds a kubectl ExecCredential for the proxy connection method.
// expirationTimestamp is written verbatim as status.expirationTimestamp (RFC3339 UTC) when
// non-zero. Callers own the early-refresh buffer: generateDPAProxyExecCredential subtracts
// proxyExecCredRefreshBuffer before passing the DPA metadata.expires_at in, and the cache
// fast path replays the already-buffered value it stored.
func BuildProxyExecCredential(certPEM, keyPEM string, expirationTimestamp time.Time) *k8smodels.IdsecSCAK8sExecCredential {
	cred := &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: proxyExecCredAPI,
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			ClientCertificateData: certPEM,
			ClientKeyData:         keyPEM,
		},
	}
	if !expirationTimestamp.IsZero() {
		cred.Status.ExpirationTimestamp = expirationTimestamp.UTC().Format(time.RFC3339)
	}
	return cred
}

// ProxyExecCredentialExpiresAt parses status.expirationTimestamp (written by
// BuildProxyExecCredential) back into a time.Time. It is the exact inverse of the
// formatting above — no buffer arithmetic is applied.
func ProxyExecCredentialExpiresAt(cred *k8smodels.IdsecSCAK8sExecCredential) (time.Time, error) {
	if cred == nil || strings.TrimSpace(cred.Status.ExpirationTimestamp) == "" {
		return time.Time{}, fmt.Errorf("ExecCredential missing expirationTimestamp")
	}
	t, err := time.Parse(time.RFC3339, cred.Status.ExpirationTimestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse expirationTimestamp: %w", err)
	}
	return t.UTC(), nil
}
