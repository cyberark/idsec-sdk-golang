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
		// AWS IAM role proxy calls DPA SSO acquire without jwe_extension_value.
		// AWS IDC permission-set proxy sets ctx.K8sToken (EKS bearer) and
		// ctx.RootCA (cluster CA); both are encrypted into the JWE for DPA.
		return &dpaProxyProvider{csp: k8smodels.CSPAWS}, nil
	case k8smodels.CSPAzure:
		// Azure AKS proxy encrypts ctx.K8sToken (AKS token) and ctx.RootCA
		// as JWE (k8s_token + root_ca) for DPA proxy→cluster mTLS.
		return &dpaProxyProvider{csp: k8smodels.CSPAzure, requireJWE: true}, nil
	default:
		return nil, fmt.Errorf("unsupported CSP for kubectl-login proxy flow: %q", csp)
	}
}

// dpaProxyProvider implements IdsecSCAK8sProxyProvider for AWS EKS and Azure AKS
// clusters reached via the DPA proxy connection method.
type dpaProxyProvider struct {
	csp        string
	requireJWE bool
}

func (p *dpaProxyProvider) CSP() string { return p.csp }

func (p *dpaProxyProvider) GenerateExecCredential(
	s *IdsecSCAK8sService,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if p.requireJWE && (ctx == nil || strings.TrimSpace(ctx.K8sToken) == "") {
		return nil, fmt.Errorf("%s proxy: K8sToken is required but was not set in the cluster context",
			strings.ToLower(p.csp))
	}
	return s.generateDPAProxyExecCredential(ctx)
}
