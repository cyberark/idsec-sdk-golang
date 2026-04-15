package k8s

import (
	"errors"
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

	// WorkspaceID is the cloud account / subscription / project identifier.
	// Optional when FQDN is provided.
	WorkspaceID string

	// TenantID is the Azure Entra tenant ID (empty for non-Azure CSPs).
	TenantID string

	// RoleID is the cloud role ARN / ID (mutually exclusive with RoleName).
	RoleID string

	// RoleName is the cloud role name (mutually exclusive with RoleID).
	RoleName string

	// Region is the AWS region, parsed from the targetId ARN in the Elevate API
	// response (e.g. "us-east-1"). Not required for Azure.
	Region string

	// FQDN is the cluster API endpoint (e.g. "xxxx.gr7.us-east-1.eks.amazonaws.com").
	// Always provided via the --fqdn CLI flag. Used as the cache key identifier.
	FQDN string
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
	case "AWS":
		return &AWSTokenProvider{}, nil
	case "AZURE":
		return &AzureTokenProvider{}, nil
	default:
		return nil, fmt.Errorf("unsupported CSP for kubectl-login: %q", csp)
	}
}

// AzureTokenProvider is a forward-compatibility stub for Azure AKS.
// Full implementation (az login + kubelogin) will be added in a future release.
type AzureTokenProvider struct{}

func (p *AzureTokenProvider) CSP() string               { return "AZURE" }
func (p *AzureTokenProvider) ElevateTTL() time.Duration { return 0 }

func (p *AzureTokenProvider) GenerateToken(
	_ *k8smodels.IdsecSCAK8sElevateResult,
	_ *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	return nil, errors.New("azure aks token generation is not yet implemented; it will be added in a future release")
}
