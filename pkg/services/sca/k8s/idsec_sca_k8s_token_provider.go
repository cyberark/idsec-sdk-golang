package k8s

import (
	"fmt"
	"strings"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// IdsecSCAK8sClusterContext carries all cluster-specific information that a token
// provider needs. All fields are sourced from CLI flags and/or derived from the
// Elevate API response — no kubeconfig file I/O is performed.
type IdsecSCAK8sClusterContext struct {
	// CSP is the cloud service provider identifier (e.g. "AWS", "AZURE").
	CSP string

	// ClusterID is the EKS cluster name, parsed from the targetId ARN in the
	// Elevate API response. Used as the x-k8s-aws-id header in the STS presign.
	ClusterID string

	// RoleID is the cloud role ARN / ID from the kubectl-login flags.
	RoleID string

	// Region is the AWS region, parsed from the targetId ARN in the Elevate API
	// response (e.g. "us-east-1"). Not required for Azure.
	Region string

	// FQDN is the cluster API endpoint (e.g. "xxxx.gr7.us-east-1.eks.amazonaws.com").
	// Always provided via the --fqdn CLI flag. Used as the cache key identifier.
	FQDN string

	// OrganizationID is the Azure Entra Directory (tenant) ID or AWS organization
	// ID, passed via --organizationId.
	OrganizationID string

	// Namespace is the optional Kubernetes namespace, passed via --namespace.
	// Forwarded to the SCA Elevate API target body as "namespace". Empty when omitted.
	Namespace string

	// ElevateToken is the raw idsec session JWT used as the Bearer token for
	// the SCA Elevate API call. AzureTokenProvider decodes it to extract the
	// elevated user's identity for validation against the az login session.
	// Empty for non-Azure CSPs.
	ElevateToken string

	// JWEExtensionValue is an optional opaque value forwarded as
	// jwe_extension_value in the DPA SSO acquire request (DPA-K8S).
	// For Azure proxy this carries the raw AKS access token acquired via az CLI;
	// for AWS IDC permission-set proxy it carries the EKS bearer token from
	// STS GetCallerIdentity presign. It is empty for AWS IAM-role proxy and all
	// direct flows. The SDK encrypts it as JWE with JSON key "k8s_token".
	JWEExtensionValue string
	// Diagnostics enables kubectl-login stderr diagnostics from token providers.
	Diagnostics bool
}

// IdsecSCAK8sTokenProvider is the interface each CSP token generator must satisfy.
//
// CSP returns the uppercase CSP identifier handled by this provider.
// ElevateTTL returns how long elevated credentials (from the Elevate API) remain
// valid; this drives the keyring cache TTL in the kubectl-login action.
// GenerateToken converts an Elevate result into the kubectl ExecCredential JSON.
type IdsecSCAK8sTokenProvider interface {
	CSP() string
	ElevateTTL() time.Duration
	GenerateToken(
		result *k8smodels.IdsecSCAK8sElevateResult,
		ctx *IdsecSCAK8sClusterContext,
	) (*k8smodels.IdsecSCAK8sExecCredential, error)
}

// GetTokenProvider returns the IdsecSCAK8sTokenProvider for the given CSP.
// The CSP string is matched case-insensitively.
func GetTokenProvider(csp string) (IdsecSCAK8sTokenProvider, error) {
	switch strings.ToUpper(strings.TrimSpace(csp)) {
	case k8smodels.CSPAWS:
		return &AWSTokenProvider{}, nil
	case k8smodels.CSPAzure:
		return &AzureTokenProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported CSP for kubectl-login: %q", csp)
	}
}
