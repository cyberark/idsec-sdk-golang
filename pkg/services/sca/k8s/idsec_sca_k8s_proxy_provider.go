// Package k8s provides the SCA Kubernetes service, including kubeconfig
// generation, cluster eligibility evaluation, Elevate-based token providers,
// and proxy exec-credential providers for direct and proxy connection methods.
package k8s

import (
	"errors"
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
// reuse package-internal helpers (e.g. the DPA SIA SSO short-lived certificate
// flow) without duplicating wiring.
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
	case "AWS":
		return &AWSProxyProvider{}, nil
	case "AZURE":
		return &AzureProxyProvider{}, nil
	case "GCP":
		return &GCPProxyProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported CSP for kubectl-login proxy flow: %q", csp)
	}
}

// AzureProxyProvider is a forward-compatibility stub for Azure AKS proxy
// connections. Full implementation will be added in a future release.
type AzureProxyProvider struct{}

// CSP returns the Azure CSP identifier.
func (p *AzureProxyProvider) CSP() string { return "AZURE" }

// GenerateExecCredential is not yet implemented for Azure AKS proxy connections.
func (p *AzureProxyProvider) GenerateExecCredential(
	_ *IdsecSCAK8sService,
	_ *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	return nil, errors.New("azure aks proxy credential generation is not yet implemented; it will be added in a future release")
}

// GCPProxyProvider is a forward-compatibility stub for GCP GKE proxy
// connections. Full implementation will be added in a future release.
type GCPProxyProvider struct{}

// CSP returns the GCP CSP identifier.
func (p *GCPProxyProvider) CSP() string { return "GCP" }

// GenerateExecCredential is not yet implemented for GCP GKE proxy connections.
func (p *GCPProxyProvider) GenerateExecCredential(
	_ *IdsecSCAK8sService,
	_ *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	return nil, errors.New("gcp gke proxy credential generation is not yet implemented; it will be added in a future release")
}
