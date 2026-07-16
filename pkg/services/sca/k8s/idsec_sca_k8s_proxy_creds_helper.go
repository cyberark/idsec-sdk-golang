package k8s

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	proxyExecCredAPI           = "client.authentication.k8s.io/v1beta1"
	proxyExecCredRefreshBuffer = 60 * time.Second
)

// clusterDiagnostics reports whether kubectl-login verbose diagnostics are enabled
// on the cluster context (set by the CLI from --verbose / IDSEC_VERBOSE).
func clusterDiagnostics(ctx *IdsecSCAK8sClusterContext) bool {
	return ctx != nil && ctx.Diagnostics
}

// kubectlLoginDiagnostic writes step-by-step kubectl-login diagnostics to stderr
// when enabled. Shared by proxy credential generation and Azure role propagation.
func kubectlLoginDiagnostic(diagnostics bool, format string, args ...any) {
	if !diagnostics {
		return
	}
	fmt.Fprintf(os.Stderr, "[kubectl-login] "+format+"\n", args...)
}

// dpaSsoJWKSResponse is the response from GET /api/adb/sso/jwks.
// The server returns a JWKS object containing one or more public keys.
type dpaSsoJWKSResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// dpaSsoJWKSKeyID builds the kid query parameter for GET /api/adb/sso/jwks:
// yyyymmdd in UTC (date only).
func dpaSsoJWKSKeyID() string {
	return time.Now().UTC().Format("20060102")
}

// fetchDPASSOPublicKey calls GET /api/adb/sso/jwks?kid=<kid> on the DPA host
// and returns the RSA public key extracted from the first matching JWK entry.
func (s *IdsecSCAK8sService) fetchDPASSOPublicKey(kid string, diagnostics bool) (*rsa.PublicKey, error) {
	if s.dpaISP == nil || s.dpaISP.ISPClient() == nil {
		return nil, fmt.Errorf("dpa client not initialized")
	}

	kubectlLoginDiagnostic(diagnostics, "fetching DPA SSO public key GET %s kid=%q", acquireDpaJwksURL, kid)

	params := map[string]string{"kid": kid}
	resp, err := s.dpaISP.ISPClient().Get(context.Background(), acquireDpaJwksURL, params)
	if err != nil {
		return nil, fmt.Errorf("GET %s failed: %w", acquireDpaJwksURL, err)
	}
	defer func(body io.ReadCloser) {
		if closeErr := body.Close(); closeErr != nil {
			s.Logger.Warning("Error closing JWKS response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned unexpected status %d", acquireDpaJwksURL, resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwksResp dpaSsoJWKSResponse
	if err := json.Unmarshal(bodyBytes, &jwksResp); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	if len(jwksResp.Keys) == 0 {
		return nil, fmt.Errorf("JWKS response contained no keys for kid=%q", kid)
	}

	// Use the first key whose kid matches, or fall back to the first key if none
	// carry a kid (server may omit it when only one key is returned).
	selected := jwksResp.Keys[0]
	for _, k := range jwksResp.Keys {
		if k.KeyID == kid {
			selected = k
			break
		}
	}

	pub, ok := selected.Key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWKS key for kid=%q is not an RSA public key (got %T)", kid, selected.Key)
	}

	kubectlLoginDiagnostic(diagnostics,
		"DPA SSO public key API response: keys=%d kid=%q n=%d bytes",
		len(jwksResp.Keys), selected.KeyID, len(pub.N.Bytes()))
	return pub, nil
}

// encryptK8STokenAsJWE encrypts k8sToken as a JWE compact serialization (RSA-OAEP-256
// key-wrap, A256GCM content encryption). The token is JSON-wrapped as {"k8s_token": <token>},
// which is the plaintext the SSO service expects for both AKS and EKS. kid is embedded in
// the JWE "kid" header so the SSO service can look up the matching private key.
func encryptK8STokenAsJWE(pubKey *rsa.PublicKey, kid, k8sToken string) (string, error) {
	payload, err := json.Marshal(map[string]string{"k8s_token": k8sToken})
	if err != nil {
		return "", fmt.Errorf("failed to marshal k8s token payload: %w", err)
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: pubKey, KeyID: kid},
		(&jose.EncrypterOptions{}).WithType("JWE"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE encrypter (alg=RSA-OAEP-256): %w", err)
	}

	jweObj, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("JWE encryption failed: %w", err)
	}

	compact, err := jweObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("JWE compact serialization failed: %w", err)
	}

	return compact, nil
}

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
