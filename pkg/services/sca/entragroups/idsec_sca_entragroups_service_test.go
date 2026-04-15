package entragroups

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	entragroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/models"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// setupEntraGroupsService creates an IdsecSCAEntraGroupsService with the given mock ISP client injected.
func setupEntraGroupsService(client *isp.IdsecISPServiceClient) *IdsecSCAEntraGroupsService {
	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecSCAEntraGroupsService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}

// ---------------------------------------------------------------------------
// Validation tests (no HTTP call — zero-value service)
// ---------------------------------------------------------------------------

func TestListTargets_validation_table(t *testing.T) {
	svc := &IdsecSCAEntraGroupsService{}
	tests := []struct {
		name string
		req  *scamodels.IdsecSCAListTargetsRequest
	}{
		{name: "nil_request", req: nil},
		{name: "empty_csp", req: &scamodels.IdsecSCAListTargetsRequest{}},
		// Non-AZURE CSPs are rejected before any network call.
		{name: "aws_rejected", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"}},
		{name: "gcp_rejected", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "GCP"}},
		{name: "ibm_rejected", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "ibm"}},
		// AZURE is valid but the service is uninitialized (no HTTP client), so it still errors.
		{name: "uninitialized_azure", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"}},
		{name: "uninitialized_azure_lowercase", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "azure"}},
		{name: "uninitialized_azure_with_workspace_id", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE", WorkspaceID: "ws-123"}},
		{name: "uninitialized_azure_with_limit", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE", Limit: 25}},
		{name: "uninitialized_azure_with_next_token", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE", NextToken: "tok123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ListTargets(tt.req)
			require.Error(t, err, "expected error for case %q, got nil (resp=%v)", tt.name, resp)
		})
	}
}

// TestListTargets_NonAzureCSP_ErrorMessage verifies the error message names the rejected CSP.
func TestListTargets_NonAzureCSP_ErrorMessage(t *testing.T) {
	svc := &IdsecSCAEntraGroupsService{}
	nonAzureCSPs := []string{"AWS", "GCP", "ibm", "oracle"}

	for _, csp := range nonAzureCSPs {
		csp := csp
		t.Run("csp_"+csp, func(t *testing.T) {
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: csp})
			require.Error(t, err)
			require.Contains(t, err.Error(), csp)
		})
	}
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — positive cases
// ---------------------------------------------------------------------------

// TestListTargets_Success verifies a well-formed 200 response is decoded correctly.
func TestListTargets_Success(t *testing.T) {
	responseJSON := `{
		"response": [
			{
				"directoryId": "dir-001",
				"groupId": "grp-abc",
				"groupName": "Security Admins"
			},
			{
				"directoryId": "dir-001",
				"groupId": "grp-xyz",
				"groupName": "Dev Team"
			}
		],
		"total": 2,
		"nextToken": ""
	}`

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 2, resp.Total)
	require.Len(t, resp.Response, 2)
	require.Equal(t, "grp-abc", resp.Response[0].GroupID)
	require.Equal(t, "Security Admins", resp.Response[0].GroupName)
	require.Equal(t, "dir-001", resp.Response[0].DirectoryID)
}

// TestListTargets_EmptyResponse verifies an empty group list is handled without error.
func TestListTargets_EmptyResponse(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 0}`,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 0, resp.Total)
	require.Empty(t, resp.Response)
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — URL path verification
// ---------------------------------------------------------------------------

// TestListTargets_URLPath verifies the exact /eligibility/groups path is used
// and that CSP input is uppercased to AZURE regardless of casing.
func TestListTargets_URLPath(t *testing.T) {
	casings := []string{"AZURE", "azure", "Azure"}

	for _, inputCSP := range casings {
		inputCSP := inputCSP
		t.Run("csp_"+inputCSP, func(t *testing.T) {
			var capturedPath string
			client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return true },
					StatusCode:   http.StatusOK,
					ResponseBody: `{"response": [], "total": 0}`,
					OnRequest: func(r *http.Request) {
						capturedPath = r.URL.Path
					},
				},
			})
			defer cleanup()

			svc := setupEntraGroupsService(client)
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: inputCSP})

			require.NoError(t, err)
			require.Equal(t, "/api/access/AZURE/eligibility/groups", capturedPath)
			// Must never hit the cloud-console endpoint (no /groups suffix there)
			require.True(t, strings.HasSuffix(capturedPath, "/groups"))
		})
	}
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — query parameter forwarding
// ---------------------------------------------------------------------------

// TestListTargets_WorkspaceID verifies workspaceId is forwarded as a query parameter.
func TestListTargets_WorkspaceID(t *testing.T) {
	var capturedQuery string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 0}`,
			OnRequest: func(r *http.Request) {
				capturedQuery = r.URL.RawQuery
			},
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:         "AZURE",
		WorkspaceID: "ws-azure-999",
	})

	require.NoError(t, err)
	require.Contains(t, capturedQuery, "workspaceId=ws-azure-999")
}

// TestListTargets_Pagination verifies limit and nextToken are forwarded as query params
// and that the response nextToken is read correctly.
func TestListTargets_Pagination(t *testing.T) {
	responseJSON := `{"response": [], "total": 100, "nextToken": "page-2-token"}`

	var capturedQuery string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				capturedQuery = r.URL.RawQuery
			},
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       "AZURE",
		Limit:     25,
		NextToken: "page-1-token",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "page-2-token", resp.NextToken)
	require.Contains(t, capturedQuery, "limit=25")
	require.Contains(t, capturedQuery, "nextToken=page-1-token")
}

// TestListTargets_WorkspaceID_NotSentWhenEmpty verifies workspaceId is omitted
// from the query when it is not provided.
func TestListTargets_WorkspaceID_NotSentWhenEmpty(t *testing.T) {
	var capturedQuery string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 0}`,
			OnRequest: func(r *http.Request) {
				capturedQuery = r.URL.RawQuery
			},
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.NoError(t, err)
	require.NotContains(t, capturedQuery, "workspaceId")
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — negative / error cases
// ---------------------------------------------------------------------------

// TestListTargets_400BadRequest verifies a 400 response is returned as an error
// with the status code present in the error message.
func TestListTargets_400BadRequest(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"message": "Bad Request"}`,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
}

// TestListTargets_404NotFound verifies a 404 response is returned as an error.
func TestListTargets_404NotFound(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusNotFound,
			ResponseBody: `{"message": "Not Found"}`,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

// TestListTargets_500InternalServerError verifies a 500 response is returned as an error.
func TestListTargets_500InternalServerError(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: `{"message": "Internal Server Error"}`,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

// TestListTargets_ErrorPropagation verifies all common HTTP error codes are propagated.
// This uses the shared helper which runs 400, 404, 500 as sub-tests automatically.
func TestListTargets_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupEntraGroupsService(client)
		_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"})
		return err
	})
}

// ---------------------------------------------------------------------------
// Elevate — validation tests
// ---------------------------------------------------------------------------

func TestElevate_validation_table(t *testing.T) {
	svc := &IdsecSCAEntraGroupsService{}
	tests := []struct {
		name string
		req  *entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest
	}{
		{name: "nil_request", req: nil},
		{name: "empty_csp", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{}},
		{name: "aws_rejected", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{CSP: "AWS", DirectoryID: "dir", Groups: "g"}},
		{name: "gcp_rejected", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{CSP: "GCP", DirectoryID: "dir", Groups: "g"}},
		{name: "missing_directory_id", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{CSP: "AZURE", Groups: "g"}},
		{name: "missing_groups", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{CSP: "AZURE", DirectoryID: "dir"}},
		{name: "uninitialized_service", req: &entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{CSP: "AZURE", DirectoryID: "dir", Groups: "g"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.Elevate(tt.req)
			require.Error(t, err, "expected error for case %q, got nil (resp=%v)", tt.name, resp)
		})
	}
}

// TestElevate_NonAzureCSP_ErrorMessage verifies the error message names the rejected CSP.
func TestElevate_NonAzureCSP_ErrorMessage(t *testing.T) {
	svc := &IdsecSCAEntraGroupsService{}
	for _, csp := range []string{"AWS", "GCP", "ibm"} {
		csp := csp
		t.Run("csp_"+csp, func(t *testing.T) {
			_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
				CSP: csp, DirectoryID: "dir", Groups: "g",
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), csp)
		})
	}
}

func TestElevate_ExceedsMaxGroupIDs(t *testing.T) {
	svc := &IdsecSCAEntraGroupsService{}
	ids := strings.Repeat("g,", 51)
	ids = ids[:len(ids)-1]
	_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
		CSP: "AZURE", DirectoryID: "dir", Groups: ids,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum")
}

// ---------------------------------------------------------------------------
// Elevate — mock HTTP server tests
// ---------------------------------------------------------------------------

func TestElevate_Success(t *testing.T) {
	responseJSON := `{
		"response": {
			"directoryId": "c5a5de91-6a2f-467e-aefa-b3f62876ec6a",
			"csp": "AZURE",
			"results": [
				{
					"sessionId": "86a4378e-ea61-408b-bdcb-337cc68657e2",
					"groupId": "57f03571-ee70-4717-a506-1eb908a4a310"
				}
			]
		}
	}`

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	resp, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
		CSP: "AZURE", DirectoryID: "c5a5de91-6a2f-467e-aefa-b3f62876ec6a", Groups: "57f03571-ee70-4717-a506-1eb908a4a310",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "c5a5de91-6a2f-467e-aefa-b3f62876ec6a", resp.Response.DirectoryID)
	require.Equal(t, "AZURE", resp.Response.CSP)
	require.Len(t, resp.Response.Results, 1)
	require.Equal(t, "57f03571-ee70-4717-a506-1eb908a4a310", resp.Response.Results[0].GroupID)
	require.NotEmpty(t, resp.Response.Results[0].SessionID)
}

func TestElevate_CommaSeparatedGroupIDs(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": {"directoryId": "d", "csp": "AZURE", "results": []}}`,
			OnRequest: func(r *http.Request) {
				capturedBody = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
		CSP: "AZURE", DirectoryID: "tenant-1", Groups: "grp-a,grp-b,grp-c",
	})

	require.NoError(t, err)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AZURE", body["csp"])
	require.Equal(t, "tenant-1", body["directory_id"])
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 3)
	for i, expectedGroup := range []string{"grp-a", "grp-b", "grp-c"} {
		target := targets[i].(map[string]interface{})
		require.Equal(t, expectedGroup, target["group_id"])
	}
}

func TestElevate_URLPath(t *testing.T) {
	var capturedPath string
	var capturedMethod string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": {"directoryId": "d", "csp": "AZURE", "results": []}}`,
			OnRequest: func(r *http.Request) {
				capturedPath = r.URL.Path
				capturedMethod = r.Method
			},
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
		CSP: "azure", DirectoryID: "tenant-001", Groups: "grp-abc",
	})

	require.NoError(t, err)
	require.Equal(t, "/api/access/elevate/groups", capturedPath)
	require.Equal(t, http.MethodPost, capturedMethod)
}

func TestElevate_400BadRequest(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"message": "Bad Request"}`,
		},
	})
	defer cleanup()

	svc := setupEntraGroupsService(client)
	_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
		CSP: "AZURE", DirectoryID: "dir", Groups: "g",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
}

func TestElevate_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupEntraGroupsService(client)
		_, err := svc.Elevate(&entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest{
			CSP: "AZURE", DirectoryID: "dir", Groups: "g",
		})
		return err
	})
}
