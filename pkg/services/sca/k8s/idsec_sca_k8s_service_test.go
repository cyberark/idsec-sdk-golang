package k8s

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

var (
	mockSvcOnce sync.Once
	mockSvc     *IdsecSCAK8sService
	mockSvcErr  error
)

func getMockService(t *testing.T) *IdsecSCAK8sService {
	mockSvcOnce.Do(func() {
		mockSvc, mockSvcErr = NewIdsecSCAK8sService(mockISPAuth())
	})
	require.NoError(t, mockSvcErr)
	return mockSvc
}

// mockListTargetsResponse matches the API response from list-clusters (see terminal output).
const mockListTargetsResponse = `{
  "response": [
    {
      "organizationId": null,
      "workspaceId": "134672441550",
      "workspaceName": "COM-NP-Int H-CloudSec-CRC-Test-1302",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::134672441550:role/k8s_sca_test_role",
        "name": "k8s_sca_test_role",
        "description": null
      },
      "target": {
        "scope": "cluster",
        "region": "us-east-1",
        "clusterId": "arn:aws:eks:us-east-1:134672441550:cluster/k8s-demo-cluster",
        "namespaceId": null,
        "fqdn": null
      }
    },
    {
      "organizationId": null,
      "workspaceId": "134672441550",
      "workspaceName": "COM-NP-Int H-CloudSec-CRC-Test-1302",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::134672441550:role/k8s_sca_test_role",
        "name": "k8s_sca_test_role",
        "description": null
      },
      "target": {
        "scope": "cluster",
        "region": "us-east-1",
        "clusterId": "arn:aws:eks:us-east-1:134672441550:cluster/k8s-demo-cluster",
        "namespaceId": null,
        "fqdn": "https://745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com"
      }
    }
  ],
  "nextToken": null,
  "total": 2
}`

// --- Negative tests: request validation ---

func TestListTargets_NilRequest(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.ListTargets(nil)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "request cannot be nil")
}

func TestListTargets_EmptyCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: ""}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

func TestListTargets_EmptyCSP_WhitespaceOnly(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "   "}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

func TestListTargets_UnsupportedCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "ibm"}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "unsupported csp")
}

func TestListTargets_InvalidLimit_TooLow(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "aws", Limit: -1}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "limit must be between 1 and 50")
}

func TestListTargets_InvalidLimit_TooHigh(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "aws", Limit: 51}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "limit must be between 1 and 50")
}

func TestListTargets_UninitializedService(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "aws"}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "not initialized")
}

// --- Positive test: verify mock response decodes correctly into the model ---

func TestListTargetsResponse_DecodesMockResponse(t *testing.T) {
	var result k8smodels.IdsecSCAk8sListClustersResponse
	err := json.Unmarshal([]byte(mockListTargetsResponse), &result)
	require.NoError(t, err)

	require.Len(t, result.Response, 2)
	require.Equal(t, 2, result.Total)
	require.Nil(t, result.NextToken)

	item := result.Response[0]
	require.NotNil(t, item)
	require.Equal(t, "134672441550", item.WorkspaceID)
	require.Equal(t, "COM-NP-Int H-CloudSec-CRC-Test-1302", item.WorkspaceName)
	require.Equal(t, "account", item.WorkspaceType)
	require.Equal(t, "arn:aws:iam::134672441550:role/k8s_sca_test_role", item.Role.ID)
	require.Equal(t, "k8s_sca_test_role", item.Role.Name)
	require.Equal(t, "cluster", item.Target.Scope)
	require.Equal(t, "us-east-1", item.Target.Region)
	require.Equal(t, "arn:aws:eks:us-east-1:134672441550:cluster/k8s-demo-cluster", item.Target.ClusterID)
	require.Nil(t, item.Target.NamespaceID)
	require.Nil(t, item.Target.FQDN)

	item2 := result.Response[1]
	require.Equal(t, "arn:aws:iam::134672441550:role/k8s_sca_test_role", item2.Role.ID)
	require.NotNil(t, item2.Target.FQDN)
	require.Equal(t, "https://745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com", *item2.Target.FQDN)
}

// --- Positive test: empty response array decodes without error ---

func TestListTargetsResponse_EmptyResponse(t *testing.T) {
	emptyJSON := `{"response": [], "total": 0}`
	var result k8smodels.IdsecSCAk8sListClustersResponse
	err := json.Unmarshal([]byte(emptyJSON), &result)
	require.NoError(t, err)
	require.Len(t, result.Response, 0)
	require.Equal(t, 0, result.Total)
}

// --- Positive test: response with multiple items decodes correctly ---

func TestListTargetsResponse_MultipleItems(t *testing.T) {
	multiJSON := `{
  "response": [
    {
      "organizationId": null,
      "workspaceId": "111111111111",
      "workspaceName": "Workspace-1",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::111111111111:role/role-1",
        "name": "role-1",
        "description": null
      },
      "target": {
        "scope": "cluster",
        "region": "us-east-1",
        "clusterId": "arn:aws:eks:us-east-1:111111111111:cluster/cluster-1",
        "namespaceId": null,
        "fqdn": null
      }
    },
    {
      "organizationId": null,
      "workspaceId": "222222222222",
      "workspaceName": "Workspace-2",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::222222222222:role/role-2",
        "name": "role-2",
        "description": null
      },
      "target": {
        "scope": "namespace",
        "region": "eu-west-1",
        "clusterId": "arn:aws:eks:eu-west-1:222222222222:cluster/cluster-2",
        "namespaceId": "ns-prod",
        "fqdn": "cluster-2.example.com"
      }
    }
  ],
  "total": 2
}`

	var result k8smodels.IdsecSCAk8sListClustersResponse
	err := json.Unmarshal([]byte(multiJSON), &result)
	require.NoError(t, err)
	require.Len(t, result.Response, 2)
	require.Equal(t, 2, result.Total)

	require.Equal(t, "111111111111", result.Response[0].WorkspaceID)
	require.Equal(t, "us-east-1", result.Response[0].Target.Region)
	require.Equal(t, "cluster", result.Response[0].Target.Scope)

	require.Equal(t, "222222222222", result.Response[1].WorkspaceID)
	require.Equal(t, "eu-west-1", result.Response[1].Target.Region)
	require.Equal(t, "namespace", result.Response[1].Target.Scope)
	require.NotNil(t, result.Response[1].Target.NamespaceID)
	require.Equal(t, "ns-prod", *result.Response[1].Target.NamespaceID)
	require.NotNil(t, result.Response[1].Target.FQDN)
	require.Equal(t, "cluster-2.example.com", *result.Response[1].Target.FQDN)
}

// --- Positive test: response with nextToken for pagination ---

func TestListTargetsResponse_WithNextToken(t *testing.T) {
	paginatedJSON := `{
  "response": [
    {
      "organizationId": null,
      "workspaceId": "134672441550",
      "workspaceName": "COM-NP-Int H-CloudSec-CRC-Test-1302",
      "workspaceType": "account",
      "role": {
        "id": "arn:aws:iam::134672441550:role/k8s_sca_test_role",
        "name": "k8s_sca_test_role",
        "description": null
      },
      "target": {
        "scope": "cluster",
        "region": "us-east-1",
        "clusterId": "arn:aws:eks:us-east-1:134672441550:cluster/k8s-demo-cluster",
        "namespaceId": null,
        "fqdn": null
      }
    }
  ],
  "nextToken": "page-2-token",
  "total": 5
}`

	var result k8smodels.IdsecSCAk8sListClustersResponse
	err := json.Unmarshal([]byte(paginatedJSON), &result)
	require.NoError(t, err)
	require.Len(t, result.Response, 1)
	require.Equal(t, 5, result.Total)
	require.NotNil(t, result.NextToken)
	require.Equal(t, "page-2-token", *result.NextToken)
}

// mockISPAuth returns a minimal IdsecISPAuth for unit tests.
func mockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-user@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata:   map[string]interface{}{"env": "dev"},
			},
		},
	}
}
