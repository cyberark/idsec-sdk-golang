// Package k8s provides the SCA Kubernetes service, including kubeconfig
// generation, cluster eligibility evaluation, Elevate-based token providers,
// and proxy exec-credential providers for direct and proxy connection methods.
package k8s

import (
	"strings"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// AWSProxyProvider implements IdsecSCAK8sProxyProvider for AWS EKS clusters
// reached via the DPA proxy connection method.
//
// AWS IAM role proxy access calls DPA SSO acquire without a jwe_extension_value.
// AWS IDC permission-set proxy access must place the EKS bearer token in
// ctx.JWEExtensionValue first; it is encrypted as JWE and forwarded so the DPA
// backend can validate cluster identity.
type AWSProxyProvider struct{}

// CSP returns the AWS CSP identifier.
func (p *AWSProxyProvider) CSP() string { return k8smodels.CSPAWS }

// GenerateExecCredential issues a kubectl ExecCredential containing the
// short-lived client certificate/key pair from DPA SSO acquire.
//
// When ctx.JWEExtensionValue is set (AWS IDC), it is forwarded as
// jwe_extension_value. IAM-role proxy leaves it empty. Diagnostics from ctx
// enables verbose kubectl-login step logs when set by the CLI.
func (p *AWSProxyProvider) GenerateExecCredential(
	s *IdsecSCAK8sService,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	jwe := ""
	if ctx != nil {
		jwe = strings.TrimSpace(ctx.JWEExtensionValue)
	}
	kubectlLoginDiagnostic(clusterDiagnostics(ctx),
		"AWSProxyProvider: forwarding jwe_extension_value len=%d", len(jwe))
	return s.generateDPAProxyExecCredential(jwe, clusterDiagnostics(ctx))
}
