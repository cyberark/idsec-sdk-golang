// Package k8s provides the SCA Kubernetes service, including kubeconfig
// generation, cluster eligibility evaluation, Elevate-based token providers,
// and proxy exec-credential providers for direct and proxy connection methods.
package k8s

import (
	"fmt"
	"strings"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// IdsecSCAK8sProxyProvider is the interface each CSP proxy credential generator
// must satisfy.
//
// CSP returns the uppercase CSP identifier handled by this provider.
// GenerateExecCredential produces a kubectl ExecCredential for the proxy
// connection method using whatever CSP-specific certificate/secret flow the
// provider needs. The shared *IdsecSCAK8sService is passed in so providers can
// reuse package-internal helpers (e.g. DPA SSO acquire via generateDPAProxyExecCredential)
// without duplicating wiring.
type IdsecSCAK8sProxyProvider interface {
	CSP() string
	GenerateExecCredential(
		s *IdsecSCAK8sService,
		ctx *IdsecSCAK8sClusterContext,
	) (*k8smodels.IdsecSCAK8sExecCredential, error)
}

// GetProxyProvider returns the IdsecSCAK8sProxyProvider for the given CSP.
// The CSP string is matched case-insensitively.
func GetProxyProvider(csp string) (IdsecSCAK8sProxyProvider, error) {
	switch strings.ToUpper(strings.TrimSpace(csp)) {
	case k8smodels.CSPAWS:
		return &AWSProxyProvider{}, nil
	case k8smodels.CSPAzure:
		return &AzureProxyProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported CSP for kubectl-login proxy flow: %q", csp)
	}
}

// AzureProxyProvider implements IdsecSCAK8sProxyProvider for Azure AKS clusters
// reached via the DPA proxy connection method.
//
// The AKS access token acquired by the CLI (via az CLI) must be placed in
// ctx.JWEExtensionValue before calling GenerateExecCredential. It is encrypted
// as JWE (k8s_token) and forwarded as jwe_extension_value in the DPA SSO
// acquire request so the DPA backend can validate the caller's Azure identity.
type AzureProxyProvider struct{}

// CSP returns the Azure CSP identifier.
func (p *AzureProxyProvider) CSP() string { return k8smodels.CSPAzure }

// GenerateExecCredential issues a kubectl ExecCredential containing the
// short-lived client certificate/key pair from DPA SSO acquire using the
// k8s token supplied in ctx.JWEExtensionValue.
func (p *AzureProxyProvider) GenerateExecCredential(
	s *IdsecSCAK8sService,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if ctx == nil || strings.TrimSpace(ctx.JWEExtensionValue) == "" {
		return nil, fmt.Errorf("azure aks proxy: JWEExtensionValue (k8s token) is required but was not set in the cluster context")
	}
	return s.generateDPAProxyExecCredential(ctx.JWEExtensionValue, ctx.Diagnostics)
}
