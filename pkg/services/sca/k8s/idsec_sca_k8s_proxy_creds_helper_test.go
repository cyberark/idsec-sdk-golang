package k8s

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const testProxyJWERootCA = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNBDQo="

// jwksBodyForRSAKey serializes the given RSA public key as a JWKS JSON response.
func jwksBodyForRSAKey(t *testing.T, kid string, pubKey *rsa.PublicKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: pubKey, KeyID: kid, Use: "enc"}
	resp := dpaSsoJWKSResponse{Keys: []jose.JSONWebKey{jwk}}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	return string(b)
}

func TestDpaSsoJWKSKeyID_Format(t *testing.T) {
	kid := dpaSsoJWKSKeyID()

	require.Len(t, kid, 8, "kid must be 8 characters (yyyymmdd)")
	_, err := time.Parse("20060102", kid)
	require.NoError(t, err, "kid must be a valid date in yyyymmdd format")
	require.Equal(t, time.Now().UTC().Format("20060102"), kid)
}

// decryptProxyJWEPayload decrypts a proxy JWE compact string and returns the JSON payload map.
func decryptProxyJWEPayload(t *testing.T, jweCompact string, privKey *rsa.PrivateKey) map[string]string {
	t.Helper()
	jweObj, err := jose.ParseEncrypted(jweCompact,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM})
	require.NoError(t, err)
	plaintext, err := jweObj.Decrypt(privKey)
	require.NoError(t, err)
	var payload map[string]string
	require.NoError(t, json.Unmarshal(plaintext, &payload),
		"decrypted plaintext must be a JSON object")
	return payload
}

func TestEncryptProxyJWEExtension_RSA_RoundTrip(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name          string
		token         string
		rootCA        string
		wantRootCA    string
		omitRootCAKey bool
	}{
		{
			name:          "token_only",
			token:         "eyJhbGciOiJSUzI1NiJ9.test-k8s-jwt-payload.sig",
			omitRootCAKey: true,
		},
		{
			name:       "token_and_root_ca",
			token:      "k8s-bearer-token",
			rootCA:     testProxyJWERootCA,
			wantRootCA: testProxyJWERootCA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kid := dpaSsoJWKSKeyID()
			jweCompact, err := encryptProxyJWEExtension(&privKey.PublicKey, kid, tt.token, tt.rootCA)
			require.NoError(t, err)
			require.NotEmpty(t, jweCompact)
			require.Len(t, strings.Split(jweCompact, "."), 5, "JWE compact must have 5 segments")

			jweObj, err := jose.ParseEncrypted(jweCompact,
				[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
				[]jose.ContentEncryption{jose.A256GCM})
			require.NoError(t, err)
			require.Equal(t, kid, jweObj.Header.KeyID, "kid must be embedded in the JWE protected header")

			payload := decryptProxyJWEPayload(t, jweCompact, privKey)
			require.Equal(t, tt.token, payload["k8s_token"])
			if tt.omitRootCAKey {
				_, hasRootCA := payload["root_ca"]
				require.False(t, hasRootCA, "root_ca must be omitted when empty")
				return
			}
			require.Equal(t, tt.wantRootCA, payload["root_ca"])
		})
	}
}

func TestFetchDPASSOPublicKey_RSA_Success(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := dpaSsoJWKSKeyID()

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "jwks")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: jwksBodyForRSAKey(t, kid, &privKey.PublicKey),
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	pubKey, err := svc.fetchDPASSOPublicKey(kid, false)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
}

func TestFetchDPASSOPublicKey_NonRSAKeyRejected(t *testing.T) {
	ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	kid := dpaSsoJWKSKeyID()

	jwk := jose.JSONWebKey{Key: &ecPrivKey.PublicKey, KeyID: kid, Use: "enc"}
	resp := dpaSsoJWKSResponse{Keys: []jose.JSONWebKey{jwk}}
	body, err := json.Marshal(resp)
	require.NoError(t, err)

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodGet },
			StatusCode:   http.StatusOK,
			ResponseBody: string(body),
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	_, err = svc.fetchDPASSOPublicKey(kid, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an RSA public key")
}

func TestFetchDPASSOPublicKey_FallbackToFirstKeyWhenKidMismatch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: "different-kid", Use: "enc"}
	resp := dpaSsoJWKSResponse{Keys: []jose.JSONWebKey{jwk}}
	body, err := json.Marshal(resp)
	require.NoError(t, err)

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodGet },
			StatusCode:   http.StatusOK,
			ResponseBody: string(body),
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	pubKey, err := svc.fetchDPASSOPublicKey(dpaSsoJWKSKeyID(), false)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
}

func TestFetchDPASSOPublicKey_NonOKStatus(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusNotFound,
			ResponseBody: `{"error":"not found"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	_, err := svc.fetchDPASSOPublicKey(dpaSsoJWKSKeyID(), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestFetchDPASSOPublicKey_EmptyKeysArray(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"keys":[]}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	_, err := svc.fetchDPASSOPublicKey(dpaSsoJWKSKeyID(), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no keys")
}

func TestFetchDPASSOPublicKey_UninitializedDPAClient(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	_, err := svc.fetchDPASSOPublicKey(dpaSsoJWKSKeyID(), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not initialized")
}

func TestParseDpaSsoExpiresAt(t *testing.T) {
	t.Parallel()
	expiresAt, err := parseDpaSsoExpiresAt(&k8smodels.IdsecSCAK8sDpaSsoAcquireMetadata{
		ExpiresAt: "2026-05-31T13:34:16.939329",
	})
	require.NoError(t, err)
	require.Equal(t, 2026, expiresAt.Year())
	require.Equal(t, time.May, expiresAt.Month())
	require.Equal(t, 31, expiresAt.Day())
	require.Equal(t, 13, expiresAt.Hour())
	require.Equal(t, 34, expiresAt.Minute())
}

func TestParseDpaSsoExpiresAt_Empty(t *testing.T) {
	t.Parallel()
	_, err := parseDpaSsoExpiresAt(&k8smodels.IdsecSCAK8sDpaSsoAcquireMetadata{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expires_at")
}

func TestBuildProxyExecCredential_ExpirationTimestamp(t *testing.T) {
	t.Parallel()
	expirationTimestamp := time.Date(2026, 5, 31, 13, 34, 16, 0, time.UTC)
	cred := BuildProxyExecCredential("CERT", "KEY", expirationTimestamp)
	require.Equal(t, "2026-05-31T13:34:16Z", cred.Status.ExpirationTimestamp)
}

func TestProxyExecCredentialExpiresAt_RoundTrip(t *testing.T) {
	t.Parallel()
	expirationTimestamp := time.Date(2026, 5, 31, 13, 34, 16, 0, time.UTC)
	cred := BuildProxyExecCredential("CERT", "KEY", expirationTimestamp)
	got, err := ProxyExecCredentialExpiresAt(cred)
	require.NoError(t, err)
	require.True(t, got.Equal(expirationTimestamp))
}
