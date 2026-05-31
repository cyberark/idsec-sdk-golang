package k8s

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// mockEvaluateResponse is the confirmed JSON shape returned by the SCA Evaluate API.
// It mirrors the sample from the Confluence spec and the actual API response.
const mockEvaluateResponse = `{
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
      },
      "connectionMethod": "direct"
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
      },
      "connectionMethod": "direct"
    }
  ],
  "nextToken": null,
  "total": 2
}`

// validEvaluateFQDNTarget is a reusable valid evaluate target using the FQDN path.
var validEvaluateFQDNTarget = k8smodels.IdsecSCAK8sEvaluateTarget{
	FQDN: "745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com",
}

// ---------------------------------------------------------------------------
// Validation tests — no HTTP call
// ---------------------------------------------------------------------------

func TestEvaluateEligibility_NilRequest(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.EvaluateEligibility(nil, "AWS")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "cannot be nil")
}

func TestEvaluateEligibility_EmptyCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}
	got, err := svc.EvaluateEligibility(req, "")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

func TestEvaluateEligibility_WhitespaceCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}
	got, err := svc.EvaluateEligibility(req, "   ")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

func TestEvaluateEligibility_UnsupportedCSP(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}
	got, err := svc.EvaluateEligibility(req, "ibm")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "unsupported csp")
}

func TestEvaluateEligibility_TargetMissingFQDNAndName(t *testing.T) {
	svc := getMockService(t)
	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{}},
	}
	got, err := svc.EvaluateEligibility(req, "AWS")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "fqdn or name")
}

func TestEvaluateEligibility_UninitializedService(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	req := &k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}
	got, err := svc.EvaluateEligibility(req, "AWS")
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "not initialized")
}

// ---------------------------------------------------------------------------
// Success tests — mock HTTP server
// ---------------------------------------------------------------------------

func TestEvaluateEligibility_Success(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockEvaluateResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Response, 2)
	require.Equal(t, 2, resp.Total)
	require.Nil(t, resp.NextToken)

	result := resp.Response[0]
	require.Nil(t, result.OrganizationID)
	require.Equal(t, "134672441550", result.WorkspaceID)
	require.Equal(t, "COM-NP-Int H-CloudSec-CRC-Test-1302", result.WorkspaceName)
	require.Equal(t, "account", result.WorkspaceType)
	require.Equal(t, "arn:aws:iam::134672441550:role/k8s_sca_test_role", result.Role.ID)
	require.Equal(t, "k8s_sca_test_role", result.Role.Name)
	require.Equal(t, "cluster", result.Target.Scope)
	require.Equal(t, "us-east-1", result.Target.Region)
	require.Equal(t, "direct", result.ConnectionMethod)

	result2 := resp.Response[1]
	require.NotNil(t, result2.Target.FQDN)
	require.Equal(t, "https://745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com", *result2.Target.FQDN)
	require.Equal(t, "direct", result2.ConnectionMethod)
}

func TestEvaluateEligibility_SuccessWithNameTarget(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockEvaluateResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{Name: "k8s-demo-cluster"}},
	}, "aws")

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Response, 2)
}

func TestEvaluateEligibility_ProxyConnectionMethod(t *testing.T) {
	const proxyResp = `{
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
        "clusterId": "arn:aws:eks:us-east-1:134672441550:cluster/k8s-proxy-cluster",
        "namespaceId": null,
        "fqdn": "proxy-cluster.gr7.us-east-1.eks.amazonaws.com"
      },
      "connectionMethod": "proxy"
    }
  ],
  "total": 1
}`
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: proxyResp,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")

	require.NoError(t, err)
	require.Len(t, resp.Response, 1)
	require.Equal(t, "proxy", resp.Response[0].ConnectionMethod)
}

// ---------------------------------------------------------------------------
// URL / method verification
// ---------------------------------------------------------------------------

func TestEvaluateEligibility_URLPath(t *testing.T) {
	var capturedMethod, capturedPath string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockEvaluateResponse,
			OnRequest: func(r *http.Request) {
				capturedMethod = r.Method
				capturedPath = r.URL.Path
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, capturedMethod, "EvaluateEligibility must use POST")
	require.Equal(t, "/access/AWS/eligibility/clusters/evaluate", capturedPath)
}

func TestEvaluateEligibility_URLPath_Azure(t *testing.T) {
	var capturedPath string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":[],"total":0}`,
			OnRequest:    func(r *http.Request) { capturedPath = r.URL.Path },
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{{FQDN: "cluster.hcp.eastus.azmk8s.io"}},
	}, "azure")
	require.NoError(t, err)
	require.Equal(t, "/access/AZURE/eligibility/clusters/evaluate", capturedPath)
}

func TestEvaluateEligibility_RequestBody(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockEvaluateResponse,
			OnRequest: func(r *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(r.Body)
				capturedBody = buf.Bytes()
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 1)

	target := targets[0].(map[string]interface{})
	require.Equal(t, validEvaluateFQDNTarget.FQDN, target["fqdn"])
}

// ---------------------------------------------------------------------------
// Error propagation tests
// ---------------------------------------------------------------------------

func TestEvaluateEligibility_400BadRequest(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"message": "Bad Request"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
}

func TestEvaluateEligibility_500InternalServerError(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: `{"message": "Internal Server Error"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestEvaluateEligibility_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupK8sElevateService(client)
		_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
			Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
		}, "AWS")
		return err
	})
}

// ---------------------------------------------------------------------------
// Model deserialization unit tests (no HTTP, pure JSON)
// ---------------------------------------------------------------------------

func TestEvaluateResponse_DecodesMockResponse(t *testing.T) {
	var result k8smodels.IdsecSCAK8sEvaluateResponse
	err := json.Unmarshal([]byte(mockEvaluateResponse), &result)
	require.NoError(t, err)

	require.Len(t, result.Response, 2)
	require.Equal(t, 2, result.Total)
	require.Nil(t, result.NextToken)

	r := result.Response[0]
	require.Nil(t, r.OrganizationID)
	require.Equal(t, "134672441550", r.WorkspaceID)
	require.Equal(t, "k8s_sca_test_role", r.Role.Name)
	require.Equal(t, "cluster", r.Target.Scope)
	require.Equal(t, "us-east-1", r.Target.Region)
	require.Nil(t, r.Target.FQDN)
	require.Equal(t, "direct", r.ConnectionMethod)

	r2 := result.Response[1]
	require.NotNil(t, r2.Target.FQDN)
	require.Equal(t, "https://745445889F087548523CF96B3D365FF0.gr7.us-east-1.eks.amazonaws.com", *r2.Target.FQDN)
	require.Equal(t, "direct", r2.ConnectionMethod)
}

func TestEvaluateResponse_EmptyResponse(t *testing.T) {
	emptyJSON := `{"response": [], "total": 0}`
	var result k8smodels.IdsecSCAK8sEvaluateResponse
	err := json.Unmarshal([]byte(emptyJSON), &result)
	require.NoError(t, err)
	require.Len(t, result.Response, 0)
	require.Equal(t, 0, result.Total)
}

func TestEvaluateResponse_WithNextToken(t *testing.T) {
	paginatedJSON := `{
  "response": [
    {
      "organizationId": null,
      "workspaceId": "134672441550",
      "workspaceName": "Test",
      "workspaceType": "account",
      "role": {"id": "role-1", "name": "role-1", "description": null},
      "target": {"scope": "cluster", "region": "us-east-1", "clusterId": "cluster-1", "namespaceId": null, "fqdn": null},
      "connectionMethod": "direct"
    }
  ],
  "nextToken": "page-2-token",
  "total": 5
}`
	var result k8smodels.IdsecSCAK8sEvaluateResponse
	err := json.Unmarshal([]byte(paginatedJSON), &result)
	require.NoError(t, err)
	require.Len(t, result.Response, 1)
	require.Equal(t, 5, result.Total)
	require.NotNil(t, result.NextToken)
	require.Equal(t, "page-2-token", *result.NextToken)
}
