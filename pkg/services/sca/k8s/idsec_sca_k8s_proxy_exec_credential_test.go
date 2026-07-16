package k8s

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
)

const mockDpaSsoAcquireResponse = `{
  "token": {
    "client_certificate": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
    "private_key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
  },
  "metadata": {
    "expires_at": "2030-06-01T12:00:00.000000"
  }
}`

func TestGenerateProxyExecCredential_UninitializedService(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "not initialized")
}

func TestGenerateProxyExecCredential_UnsupportedCSP(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("ibm", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "unsupported CSP for kubectl-login proxy flow")
}

func TestGenerateProxyExecCredential_AzureMissingJWE(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("AZURE", &IdsecSCAK8sClusterContext{CSP: "AZURE"})
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "JWEExtensionValue")
}

func TestGenerateProxyExecCredential_Success(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost },
			StatusCode:   http.StatusCreated,
			ResponseBody: mockDpaSsoAcquireResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", &IdsecSCAK8sClusterContext{CSP: "AWS"})
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, "client.authentication.k8s.io/v1beta1", cred.APIVersion)
	require.Equal(t, "ExecCredential", cred.Kind)
	require.Contains(t, cred.Status.ClientCertificateData, "CERT")
	require.Contains(t, cred.Status.ClientKeyData, "KEY")
	require.NotEmpty(t, cred.Status.ExpirationTimestamp)
}

func TestGenerateProxyExecCredential_MissingExpiresAt(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"token":{"client_certificate":"CERT","private_key":"KEY"},"metadata":{}}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "expires_at")
}

func TestGenerateProxyExecCredential_MissingCertificateInResponse(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"token": {}}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "proxy client certificate generation failed")
}

func TestGenerateProxyExecCredential_WithJWE(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var capturedBody map[string]interface{}
	var capturedJWKSKid string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "jwks"):
			capturedJWKSKid = r.URL.Query().Get("kid")
			jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: capturedJWKSKid, Use: "enc"}
			resp := dpaSsoJWKSResponse{Keys: []jose.JSONWebKey{jwk}}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(mockDpaSsoAcquireResponse))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL
	ispClient := &isp.IdsecISPServiceClient{IdsecClient: client}

	svc := setupK8sElevateService(ispClient)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, ispClient)
	svc.dpaISP = dpaBase

	const rawK8SToken = "k8s-jwt-token"
	cred, err := svc.generateDPAProxyExecCredential(rawK8SToken, false)
	require.NoError(t, err)
	require.NotNil(t, cred)

	require.NotEmpty(t, capturedJWKSKid)
	require.Len(t, capturedJWKSKid, 8, "kid must be yyyymmdd")
	_, parseErr := time.Parse("20060102", capturedJWKSKid)
	require.NoError(t, parseErr, "kid must be a valid date in yyyymmdd format")

	jweValue, ok := capturedBody["jwe_extension_value"].(string)
	require.True(t, ok, "jwe_extension_value must be a string")
	require.NotEqual(t, rawK8SToken, jweValue, "jwe_extension_value must be encrypted, not the raw token")
	require.Len(t, strings.Split(jweValue, "."), 5, "jwe_extension_value must be a JWE compact string (5 segments)")

	jweObj, parseErr := jose.ParseEncrypted(jweValue,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM})
	require.NoError(t, parseErr)
	plaintext, decryptErr := jweObj.Decrypt(privKey)
	require.NoError(t, decryptErr)

	var payload map[string]string
	require.NoError(t, json.Unmarshal(plaintext, &payload),
		"decrypted jwe_extension_value must be a JSON object")
	require.Equal(t, rawK8SToken, payload["k8s_token"],
		"k8s token must be JSON-wrapped under the k8s_token key before encryption")
}

func TestGenerateProxyExecCredential_Non201Status(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"error":"bad request"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.generateDPAProxyExecCredential("", false)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "proxy client certificate generation failed")
	require.Contains(t, err.Error(), "400")
}
