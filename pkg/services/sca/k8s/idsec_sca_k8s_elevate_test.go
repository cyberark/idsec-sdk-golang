package k8s

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// mockElevateResponse is the confirmed JSON shape returned by the SCA Elevate API for AWS.
// accessCredentials is a JSON-encoded string (double-encoded).
// targetId is the EKS cluster ARN from which region and cluster name are parsed.
const mockElevateResponse = `{
  "response": {
    "organizationId": "general",
    "csp": "AWS",
    "results": [
      {
        "workspaceId": "123456789012",
        "roleId": "arn:aws:iam::123456789012:role/k8s_sca_test_role",
        "sessionId": "11111111-2222-3333-4444-555555555555",
        "accessCredentials": "{\"aws_access_key\": \"DUMMYACCESSKEYID00001\", \"aws_secret_access_key\": \"dummy-secret-key\", \"aws_session_token\": \"dummy-session-token\"}",
        "targetId": "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster"
      }
    ]
  }
}`

// validFQDNReq is a reusable valid elevate request using the FQDN path (as used by kubeconfig).
var validFQDNReq = k8smodels.IdsecSCAK8sElevateKubectlRequest{
	CSP:    "AWS",
	FQDN:   "ABCD1234EFGH5678IJKL9012MNOP3456.gr7.us-east-1.eks.amazonaws.com",
	RoleID: "arn:aws:iam::123456789012:role/k8s_sca_test_role",
}

// setupK8sElevateService creates an IdsecSCAK8sService with a mock ISP client injected.
func setupK8sElevateService(client *isp.IdsecISPServiceClient) *IdsecSCAK8sService {
	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))
	return &IdsecSCAK8sService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
}

// ---------------------------------------------------------------------------
// Validation tests — no HTTP call, zero-value or minimal service
// ---------------------------------------------------------------------------

func TestElevate_NilRequest(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.Elevate(nil)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "cannot be nil")
}

func TestElevate_EmptyCSP(t *testing.T) {
	svc := getMockService(t)
	req := validFQDNReq
	req.CSP = ""
	got, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

func TestElevate_WhitespaceCSP(t *testing.T) {
	svc := getMockService(t)
	req := validFQDNReq
	req.CSP = "   "
	got, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "csp cannot be empty")
}

// TestElevate_MissingClusterIdentifier verifies that a request without FQDN and
// without both WorkspaceID+TargetID is rejected.
func TestElevate_MissingClusterIdentifier(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:    "AWS",
		RoleID: "arn:aws:iam::111111111111:role/test-role",
	})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "fqdn or (workspaceId + targetId)")
}

// TestElevate_WorkspaceIDWithoutTargetID verifies that WorkspaceID alone (without
// TargetID or FQDN) is rejected.
func TestElevate_WorkspaceIDWithoutTargetID(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:         "AWS",
		WorkspaceID: "111111111111",
		RoleID:      "arn:aws:iam::111111111111:role/test-role",
	})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "fqdn or (workspaceId + targetId)")
}

// TestElevate_TargetIDWithoutWorkspaceID verifies that TargetID alone (without
// WorkspaceID or FQDN) is rejected.
func TestElevate_TargetIDWithoutWorkspaceID(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:      "AWS",
		TargetID: "arn:aws:eks:us-east-1:111111111111:cluster/my-cluster",
		RoleID:   "arn:aws:iam::111111111111:role/test-role",
	})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "fqdn or (workspaceId + targetId)")
}

func TestElevate_MissingRoleIDAndRoleName(t *testing.T) {
	svc := getMockService(t)
	got, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:  "AWS",
		FQDN: "cluster.eks.amazonaws.com",
	})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "roleId or roleName")
}

func TestElevate_UninitializedService(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	req := validFQDNReq
	got, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "not initialized")
}

// ---------------------------------------------------------------------------
// Success tests — mock HTTP server
// ---------------------------------------------------------------------------

func TestElevate_Success_AWS(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	resp, err := svc.Elevate(&req)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "general", resp.Response.OrganizationID)
	require.Equal(t, "AWS", resp.Response.CSP)
	require.Len(t, resp.Response.Results, 1)

	result := resp.Response.Results[0]
	require.Equal(t, "123456789012", result.WorkspaceID)
	require.Equal(t, "arn:aws:iam::123456789012:role/k8s_sca_test_role", result.RoleID)
	require.Equal(t, "11111111-2222-3333-4444-555555555555", result.SessionID)
	require.NotEmpty(t, result.AccessCredentials)
	// TargetID is returned by the API and used to derive region + cluster name
	require.Equal(t, "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster", result.TargetID)
}

// TestElevate_Success_WorkspaceIDAndTargetID verifies the alternative path where
// both WorkspaceID and TargetID are provided (instead of FQDN).
func TestElevate_Success_WorkspaceIDAndTargetID(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:         "AWS",
		WorkspaceID: "123456789012",
		TargetID:    "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster",
		RoleID:      "arn:aws:iam::123456789012:role/k8s_sca_test_role",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Results, 1)
	require.Equal(t, "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster", resp.Response.Results[0].TargetID)
}

// TestElevate_WithRoleName verifies that roleName can be used instead of roleId.
func TestElevate_WithRoleName(t *testing.T) {
	const mockResp = `{
  "response": {
    "organizationId": "general",
    "csp": "AWS",
    "results": [{"workspaceId": "123", "roleName": "my-role", "sessionId": "sess-1", "accessCredentials": "{}"}]
  }
}`
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockResp,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:      "AWS",
		FQDN:     "cluster.gr7.us-east-1.eks.amazonaws.com",
		RoleName: "my-role",
	})
	require.NoError(t, err)
	require.Len(t, resp.Response.Results, 1)
	require.Equal(t, "my-role", resp.Response.Results[0].RoleName)
}

// TestElevate_AzureEmptyAccessCredentials verifies that Azure responses with no
// accessCredentials field decode without error.
func TestElevate_AzureEmptyAccessCredentials(t *testing.T) {
	const azureResp = `{
  "response": {
    "organizationId": "general",
    "csp": "AZURE",
    "results": [{"workspaceId": "sub-00000000-1111-2222-3333-444444444444", "roleId": "role-1", "sessionId": "sess-az-1"}]
  }
}`
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: azureResp,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	resp, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:    "AZURE",
		FQDN:   "mycluster.hcp.eastus.azmk8s.io",
		RoleID: "role-1",
	})
	require.NoError(t, err)
	require.Len(t, resp.Response.Results, 1)
	require.Empty(t, resp.Response.Results[0].AccessCredentials)
}

// ---------------------------------------------------------------------------
// URL / method verification
// ---------------------------------------------------------------------------

// TestElevate_URLPath verifies the exact HTTP path and method used for the elevate call.
func TestElevate_URLPath(t *testing.T) {
	var capturedMethod, capturedPath string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
			OnRequest: func(r *http.Request) {
				capturedMethod = r.Method
				capturedPath = r.URL.Path
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	_, err := svc.Elevate(&req)
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, capturedMethod, "Elevate must use POST")
	require.Equal(t, "/access/elevate/clusters", capturedPath)
}

// TestElevate_RequestBody_FQDN verifies the POST body when using the FQDN path
// (as used by the kubeconfig).
func TestElevate_RequestBody_FQDN(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
			OnRequest: func(r *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(r.Body)
				capturedBody = buf.Bytes()
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	_, err := svc.Elevate(&req)
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AWS", body["csp"])

	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 1)

	target := targets[0].(map[string]interface{})
	require.Equal(t, "ABCD1234EFGH5678IJKL9012MNOP3456.gr7.us-east-1.eks.amazonaws.com", target["fqdn"])
	require.Equal(t, "arn:aws:iam::123456789012:role/k8s_sca_test_role", target["roleId"])
}

// TestElevate_RequestBody_WorkspaceAndTargetID verifies the POST body when using
// the WorkspaceID+TargetID path.
func TestElevate_RequestBody_WorkspaceAndTargetID(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
			OnRequest: func(r *http.Request) {
				buf := new(bytes.Buffer)
				_, _ = buf.ReadFrom(r.Body)
				capturedBody = buf.Bytes()
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:         "AWS",
		WorkspaceID: "123456789012",
		TargetID:    "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster",
		RoleID:      "arn:aws:iam::123456789012:role/k8s_sca_test_role",
	})
	require.NoError(t, err)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AWS", body["csp"])

	targets := body["targets"].([]interface{})
	target := targets[0].(map[string]interface{})
	require.Equal(t, "123456789012", target["workspaceId"])
	require.Equal(t, "arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster", target["targetId"])
	require.Equal(t, "arn:aws:iam::123456789012:role/k8s_sca_test_role", target["roleId"])
}

// ---------------------------------------------------------------------------
// Error propagation tests
// ---------------------------------------------------------------------------

func TestElevate_400BadRequest(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"message": "Bad Request"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	_, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
}

func TestElevate_404NotFound(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusNotFound,
			ResponseBody: `{"message": "Not Found"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	_, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestElevate_500InternalServerError(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: `{"message": "Internal Server Error"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	req := validFQDNReq
	_, err := svc.Elevate(&req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestElevate_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupK8sElevateService(client)
		req := validFQDNReq
		_, err := svc.Elevate(&req)
		return err
	})
}

// ---------------------------------------------------------------------------
// Model deserialization unit tests (no HTTP, pure JSON)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Token provider unit tests
// ---------------------------------------------------------------------------

func TestGetTokenProvider_AWS(t *testing.T) {
	p, err := GetTokenProvider("AWS")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, "AWS", p.CSP())
	require.Equal(t, awsElevateTTL, p.ElevateTTL())
}

func TestGetTokenProvider_AWSLowercase(t *testing.T) {
	p, err := GetTokenProvider("aws")
	require.NoError(t, err)
	require.Equal(t, "AWS", p.CSP())
}

func TestGetTokenProvider_AZURE(t *testing.T) {
	p, err := GetTokenProvider("AZURE")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, "AZURE", p.CSP())
}

func TestGetTokenProvider_Unsupported(t *testing.T) {
	_, err := GetTokenProvider("GCP")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestAzureTokenProvider_GenerateToken_NotImplemented(t *testing.T) {
	p := &AzureTokenProvider{}
	_, err := p.GenerateToken(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not yet implemented")
}

func TestAWSTokenProvider_GenerateToken_EmptyAccessCredentials(t *testing.T) {
	p := &AWSTokenProvider{}
	result := &k8smodels.IdsecSCAK8sElevateResult{AccessCredentials: ""}
	ctx := &IdsecSCAK8sClusterContext{Region: "us-east-1", ClusterID: "my-cluster"}
	_, err := p.GenerateToken(result, ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "accessCredentials is empty")
}

func TestAWSTokenProvider_GenerateToken_InvalidJSON(t *testing.T) {
	p := &AWSTokenProvider{}
	result := &k8smodels.IdsecSCAK8sElevateResult{AccessCredentials: "{not-valid-json}"}
	ctx := &IdsecSCAK8sClusterContext{Region: "us-east-1", ClusterID: "my-cluster"}
	_, err := p.GenerateToken(result, ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse AWS access credentials")
}

func TestAWSTokenProvider_GenerateToken_MissingAccessKey(t *testing.T) {
	p := &AWSTokenProvider{}
	result := &k8smodels.IdsecSCAK8sElevateResult{
		AccessCredentials: `{"aws_access_key": "", "aws_secret_access_key": "secret", "aws_session_token": "token"}`,
	}
	ctx := &IdsecSCAK8sClusterContext{Region: "us-east-1", ClusterID: "my-cluster"}
	_, err := p.GenerateToken(result, ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing")
}

// ---------------------------------------------------------------------------
// ParseEKSARN tests
// ---------------------------------------------------------------------------

func TestParseEKSARN_Valid(t *testing.T) {
	region, clusterName, err := ParseEKSARN("arn:aws:eks:us-east-1:123456789012:cluster/k8s-demo-cluster")
	require.NoError(t, err)
	require.Equal(t, "us-east-1", region)
	require.Equal(t, "k8s-demo-cluster", clusterName)
}

func TestParseEKSARN_DifferentRegion(t *testing.T) {
	region, clusterName, err := ParseEKSARN("arn:aws:eks:eu-west-1:999888777666:cluster/prod-cluster")
	require.NoError(t, err)
	require.Equal(t, "eu-west-1", region)
	require.Equal(t, "prod-cluster", clusterName)
}

func TestParseEKSARN_InvalidPrefix(t *testing.T) {
	_, _, err := ParseEKSARN("arn:aws:iam::123456789012:role/k8s_sca_test_role")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid EKS ARN")
}

func TestParseEKSARN_EmptyString(t *testing.T) {
	_, _, err := ParseEKSARN("")
	require.Error(t, err)
}

func TestParseEKSARN_MissingClusterPrefix(t *testing.T) {
	_, _, err := ParseEKSARN("arn:aws:eks:us-east-1:123456789012:nodegroup/my-ng")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cluster/")
}

func TestParseEKSARN_EmptyClusterName(t *testing.T) {
	_, _, err := ParseEKSARN("arn:aws:eks:us-east-1:123456789012:cluster/")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cluster name is empty")
}

func TestParseEKSARN_RandomString(t *testing.T) {
	_, _, err := ParseEKSARN("not-an-arn-at-all")
	require.Error(t, err)
}
