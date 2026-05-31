package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetProxyProvider(t *testing.T) {
	tests := []struct {
		name        string
		csp         string
		expectErr   bool
		expectedCSP string
	}{
		{name: "success_aws_upper", csp: "AWS", expectedCSP: "AWS"},
		{name: "success_aws_lower", csp: "aws", expectedCSP: "AWS"},
		{name: "success_aws_padded", csp: "  aws  ", expectedCSP: "AWS"},
		{name: "success_azure", csp: "azure", expectedCSP: "AZURE"},
		{name: "success_gcp", csp: "GCP", expectedCSP: "GCP"},
		{name: "error_empty", csp: "", expectErr: true},
		{name: "error_unknown", csp: "ibm", expectErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := GetProxyProvider(tt.csp)
			if tt.expectErr {
				require.Error(t, err)
				require.Nil(t, p)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)
			require.Equal(t, tt.expectedCSP, p.CSP())
		})
	}
}

func TestAzureProxyProvider_GenerateExecCredential_NotImplemented(t *testing.T) {
	p := &AzureProxyProvider{}
	require.Equal(t, "AZURE", p.CSP())
	cred, err := p.GenerateExecCredential(nil, nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "azure aks proxy credential generation is not yet implemented")
}

func TestGCPProxyProvider_GenerateExecCredential_NotImplemented(t *testing.T) {
	p := &GCPProxyProvider{}
	require.Equal(t, "GCP", p.CSP())
	cred, err := p.GenerateExecCredential(nil, nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "gcp gke proxy credential generation is not yet implemented")
}

func TestAWSProxyProvider_CSP(t *testing.T) {
	p := &AWSProxyProvider{}
	require.Equal(t, "AWS", p.CSP())
}
