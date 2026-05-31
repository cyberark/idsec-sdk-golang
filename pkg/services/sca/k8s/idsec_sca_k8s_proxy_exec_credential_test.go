package k8s

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
)

type mockProxyCertificateProvider struct {
	req *ssomodels.IdsecSIASSOGetShortLivedClientCertificate
	err error
}

func (m *mockProxyCertificateProvider) ShortLivedClientCertificate(req *ssomodels.IdsecSIASSOGetShortLivedClientCertificate) error {
	m.req = req
	return m.err
}

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

func TestGenerateProxyExecCredential_AzureStub(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("AZURE", &IdsecSCAK8sClusterContext{CSP: "AZURE"})
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "azure aks proxy credential generation is not yet implemented")
}

func TestGenerateProxyExecCredential_GCPStub(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("gcp", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "gcp gke proxy credential generation is not yet implemented")
}

func TestGenerateProxyExecCredential_Success(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	provider := &mockProxyCertificateProvider{}
	proxyBase := &services.IdsecISPBaseService{}
	svc.dpaSSOISP = proxyBase
	var providerBase *services.IdsecISPBaseService
	certPath := "/tmp/idsec-k8s-proxy-test/user_client_cert.crt"
	keyPath := "/tmp/idsec-k8s-proxy-test/user_client_key.pem"
	tempDirPath := "/tmp/idsec-k8s-proxy-test"
	var removedPath string

	origProviderFactory := newSCAProxyCertificateProvider
	origMakeTempDir := makeTempDir
	origRemoveAll := removeAll
	origGlobFiles := globFiles
	origReadFile := readFile
	t.Cleanup(func() {
		newSCAProxyCertificateProvider = origProviderFactory
		makeTempDir = origMakeTempDir
		removeAll = origRemoveAll
		globFiles = origGlobFiles
		readFile = origReadFile
	})

	newSCAProxyCertificateProvider = func(base *services.IdsecISPBaseService) (scaK8sProxyCertificateProvider, error) {
		providerBase = base
		return provider, nil
	}
	makeTempDir = func(_, _ string) (string, error) { return tempDirPath, nil }
	removeAll = func(path string) error {
		removedPath = path
		return nil
	}
	globFiles = func(pattern string) ([]string, error) {
		switch {
		case strings.HasSuffix(pattern, "*_client_cert.crt"):
			return []string{certPath}, nil
		case strings.HasSuffix(pattern, "*_client_key.pem"):
			return []string{keyPath}, nil
		default:
			return nil, nil
		}
	}
	readFile = func(path string) ([]byte, error) {
		switch path {
		case certPath:
			return []byte("CERT_DATA"), nil
		case keyPath:
			return []byte("KEY_DATA"), nil
		default:
			return nil, fmt.Errorf("unexpected read path: %s", path)
		}
	}

	cred, err := svc.GenerateProxyExecCredential("AWS", &IdsecSCAK8sClusterContext{CSP: "AWS"})
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, "client.authentication.k8s.io/v1beta1", cred.APIVersion)
	require.Equal(t, "ExecCredential", cred.Kind)
	require.Equal(t, "CERT_DATA", cred.Status.ClientCertificateData)
	require.Equal(t, "KEY_DATA", cred.Status.ClientKeyData)

	require.NotNil(t, provider.req)
	require.Same(t, proxyBase, providerBase)
	require.Equal(t, "DPA-K8S", provider.req.Service)
	require.Equal(t, ssomodels.File, provider.req.OutputFormat)
	require.Equal(t, tempDirPath, provider.req.Folder)
	require.False(t, provider.req.AllowCaching)
	require.Equal(t, tempDirPath, removedPath)
}

func TestGenerateProxyExecCredential_MissingCertificateFiles(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	provider := &mockProxyCertificateProvider{}

	origProviderFactory := newSCAProxyCertificateProvider
	origMakeTempDir := makeTempDir
	origRemoveAll := removeAll
	origGlobFiles := globFiles
	origReadFile := readFile
	t.Cleanup(func() {
		newSCAProxyCertificateProvider = origProviderFactory
		makeTempDir = origMakeTempDir
		removeAll = origRemoveAll
		globFiles = origGlobFiles
		readFile = origReadFile
	})

	newSCAProxyCertificateProvider = func(_ *services.IdsecISPBaseService) (scaK8sProxyCertificateProvider, error) {
		return provider, nil
	}
	makeTempDir = func(_, _ string) (string, error) { return "/tmp/idsec-k8s-proxy-missing", nil }
	removeAll = func(string) error { return nil }
	globFiles = func(_ string) ([]string, error) { return []string{}, nil }
	readFile = func(string) ([]byte, error) { return nil, nil }

	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "files not found")
}
