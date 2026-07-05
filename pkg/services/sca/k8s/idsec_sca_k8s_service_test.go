package k8s

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
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

func setupK8sListTargetsService(client *isp.IdsecISPServiceClient) *IdsecSCAK8sService {
	ispBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(ispBase, client)

	return &IdsecSCAK8sService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}

func TestSupportedCSPsForKubeconfigGeneration(t *testing.T) {
	require.ElementsMatch(t, []string{"aws", "azure"}, SupportedCSPs)
}

func TestDPAGenerateKubeconfigCSPSegment(t *testing.T) {
	require.Equal(t, "AWS", dpaGenerateKubeconfigCSPSegment("aws"))
	require.Equal(t, "azure_resource", dpaGenerateKubeconfigCSPSegment("azure"))
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
	svc := &IdsecSCAK8sService{}
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: ""}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "not initialized")
}

func TestListTargets_EmptyCSP_WhitespaceOnly(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "   "}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "not initialized")
}

func TestListTargets_UnsupportedCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "ibm"}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "unsupported csp")
}

func TestListTargets_CSPAndAll(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAk8sListClustersRequest{CSP: "aws", All: true}
	got, err := svc.ListTargets(req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "choose either csp or all")
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

func TestListTargets_AllFlag_AggregatesAWSAndAzure(t *testing.T) {
	var capturedPaths []string
	var capturedQueries []string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/access/AWS/eligibility/clusters" && r.URL.Query().Get("nextToken") == ""
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "aws-001", "workspaceName": "AWS Account", "workspaceType": "account"}],
				"total": 2,
				"nextToken": "aws-page-2"
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/access/AWS/eligibility/clusters" && r.URL.Query().Get("nextToken") == "aws-page-2"
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "aws-002", "workspaceName": "AWS Account 2", "workspaceType": "account"}],
				"total": 2
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/access/AZURE/eligibility/clusters" && r.URL.Query().Get("nextToken") == ""
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "azure-001", "workspaceName": "Azure Subscription", "workspaceType": "subscription"}],
				"total": 2,
				"nextToken": "azure-page-2"
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/access/AZURE/eligibility/clusters" && r.URL.Query().Get("nextToken") == "azure-page-2"
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "azure-002", "workspaceName": "Azure Subscription 2", "workspaceType": "subscription"}],
				"total": 2
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
	})
	defer cleanup()

	svc := setupK8sListTargetsService(client)
	resp, err := svc.ListTargets(&k8smodels.IdsecSCAk8sListClustersRequest{All: true})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 4, resp.Total)
	require.Empty(t, resp.Response)
	require.Len(t, resp.Responses, 2)
	require.Len(t, resp.Responses["aws"].Response, 2)
	require.Equal(t, 2, resp.Responses["aws"].Total)
	require.Len(t, resp.Responses["azure"].Response, 2)
	require.Equal(t, 2, resp.Responses["azure"].Total)
	require.Nil(t, resp.NextToken)
	require.Empty(t, resp.Errors)
	require.ElementsMatch(t, []string{"/access/AWS/eligibility/clusters", "/access/AWS/eligibility/clusters", "/access/AZURE/eligibility/clusters", "/access/AZURE/eligibility/clusters"}, capturedPaths)
	require.Contains(t, capturedQueries, "nextToken=aws-page-2")
	require.Contains(t, capturedQueries, "nextToken=azure-page-2")

	output, err := json.Marshal(resp)
	require.NoError(t, err)
	require.Contains(t, string(output), `"aws"`)
	require.Contains(t, string(output), `"azure"`)
	require.NotContains(t, string(output), `"responses"`)
	require.NotContains(t, string(output), `"response":null`)
}

func TestListTargets_EmptyCSP_PartialSuccessReturnsErrorsInResponse(t *testing.T) {
	tests := []struct {
		name                string
		awsStatus           int
		awsResponseBody     string
		azureStatus         int
		azureResponseBody   string
		expectedWorkspaceID string
		expectedErrorCSP    string
		expectedSuccessCSP  string
	}{
		{
			name:            "aws_fails_azure_succeeds",
			awsStatus:       http.StatusInternalServerError,
			awsResponseBody: `{"message": "aws unavailable"}`,
			azureStatus:     http.StatusOK,
			azureResponseBody: `{
				"response": [{"workspaceId": "azure-001", "workspaceName": "Azure Subscription", "workspaceType": "subscription"}],
				"total": 1
			}`,
			expectedWorkspaceID: "azure-001",
			expectedErrorCSP:    "aws",
			expectedSuccessCSP:  "azure",
		},
		{
			name:      "azure_fails_aws_succeeds",
			awsStatus: http.StatusOK,
			awsResponseBody: `{
				"response": [{"workspaceId": "aws-001", "workspaceName": "AWS Account", "workspaceType": "account"}],
				"total": 1
			}`,
			azureStatus:         http.StatusInternalServerError,
			azureResponseBody:   `{"message": "azure unavailable"}`,
			expectedWorkspaceID: "aws-001",
			expectedErrorCSP:    "azure",
			expectedSuccessCSP:  "aws",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return r.URL.Path == "/access/AWS/eligibility/clusters" },
					StatusCode:   tt.awsStatus,
					ResponseBody: tt.awsResponseBody,
				},
				{
					Matcher:      func(r *http.Request) bool { return r.URL.Path == "/access/AZURE/eligibility/clusters" },
					StatusCode:   tt.azureStatus,
					ResponseBody: tt.azureResponseBody,
				},
			})
			defer cleanup()

			svc := setupK8sListTargetsService(client)
			resp, err := svc.ListTargets(&k8smodels.IdsecSCAk8sListClustersRequest{})

			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, 1, resp.Total)
			require.Empty(t, resp.Response)
			require.Len(t, resp.Responses, 1)
			require.Len(t, resp.Responses[tt.expectedSuccessCSP].Response, 1)
			require.Equal(t, tt.expectedWorkspaceID, resp.Responses[tt.expectedSuccessCSP].Response[0].WorkspaceID)
			require.Len(t, resp.Errors, 1)
			require.Contains(t, resp.Errors[tt.expectedErrorCSP], "API call failed: ")
			require.Contains(t, resp.Errors[tt.expectedErrorCSP], "500")

			output, err := json.Marshal(resp)
			require.NoError(t, err)
			require.Contains(t, string(output), `"`+tt.expectedSuccessCSP+`"`)
			require.Contains(t, string(output), `"`+tt.expectedErrorCSP+`"`)
			require.NotContains(t, string(output), `"responses"`)
			require.NotContains(t, string(output), `"errors"`)
		})
	}
}

func TestListTargets_EmptyCSP_AllCSPsFailReturnsErrorsInResponse(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: `{"message": "unavailable"}`,
		},
	})
	defer cleanup()

	svc := setupK8sListTargetsService(client)
	resp, err := svc.ListTargets(&k8smodels.IdsecSCAk8sListClustersRequest{})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Response)
	require.Empty(t, resp.Responses)
	require.Equal(t, 0, resp.Total)
	require.Len(t, resp.Errors, 2)
	require.Contains(t, resp.Errors["aws"], "API call failed: ")
	require.Contains(t, resp.Errors["aws"], "500")
	require.Contains(t, resp.Errors["azure"], "API call failed: ")
	require.Contains(t, resp.Errors["azure"], "500")
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
