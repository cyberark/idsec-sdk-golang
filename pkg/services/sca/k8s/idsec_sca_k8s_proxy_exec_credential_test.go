package k8s

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
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
	var capturedBody map[string]interface{}
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost },
			StatusCode:   http.StatusCreated,
			ResponseBody: mockDpaSsoAcquireResponse,
			OnRequest: func(r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	ctx := &IdsecSCAK8sClusterContext{CSP: "AZURE", JWEExtensionValue: "aks-jwt-token"}
	// Directly test the inner function with a JWE value
	cred, err := svc.generateDPAProxyExecCredential("aks-jwt-token")
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, "aks-jwt-token", capturedBody["jwe_extension_value"])
	_ = ctx
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

	cred, err := svc.generateDPAProxyExecCredential("")
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "proxy client certificate generation failed")
	require.Contains(t, err.Error(), "400")
}
