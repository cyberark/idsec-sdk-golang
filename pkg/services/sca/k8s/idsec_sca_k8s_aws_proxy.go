// Package k8s provides the SCA Kubernetes service, including kubeconfig
// generation, cluster eligibility evaluation, Elevate-based token providers,
// and proxy exec-credential providers for direct and proxy connection methods.
package k8s

import (
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// AWSProxyProvider implements IdsecSCAK8sProxyProvider for AWS EKS clusters
// reached via the DPA proxy connection method.
//
// AWS proxy access uses the shared DPA SSO acquire flow (DPA-K8S); no AWS-specific
// certificate material is required
// at this layer because the proxy itself terminates the cluster API connection.
type AWSProxyProvider struct{}

// CSP returns the AWS CSP identifier.
func (p *AWSProxyProvider) CSP() string { return k8smodels.CSPAWS }

// GenerateExecCredential issues a kubectl ExecCredential containing the
// short-lived client certificate/key pair from DPA SSO acquire.
//
// The cluster context is currently unused for AWS proxy because the DPA
// endpoint identifies the cluster from the request URL embedded in the
// kubeconfig (server field), not from request-body parameters.
func (p *AWSProxyProvider) GenerateExecCredential(
	s *IdsecSCAK8sService,
	_ *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	return s.generateDPAProxyExecCredential("")
}
