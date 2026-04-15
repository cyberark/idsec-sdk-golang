package cloudconsole

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
	cloudconsolemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole/models"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// setupCloudConsoleService creates an IdsecSCACloudConsoleService with the given mock ISP client injected.
func setupCloudConsoleService(client *isp.IdsecISPServiceClient) *IdsecSCACloudConsoleService {
	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecSCACloudConsoleService{
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
	svc := &IdsecSCACloudConsoleService{}
	tests := []struct {
		name string
		req  *scamodels.IdsecSCAListTargetsRequest
	}{
		{name: "nil_request", req: nil},
		{name: "empty_csp", req: &scamodels.IdsecSCAListTargetsRequest{}},
		{name: "unsupported_csp_ibm", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "ibm"}},
		{name: "unsupported_csp_oracle", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "oracle"}},
		{name: "unsupported_csp_mixed_case", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "Ibm"}},
		// All supported CSPs still fail here because the service is uninitialized (no HTTP client).
		{name: "uninitialized_aws", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"}},
		{name: "uninitialized_azure", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"}},
		{name: "uninitialized_gcp", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "GCP"}},
		{name: "uninitialized_aws_with_workspace_id", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS", WorkspaceID: "ws-123"}},
		{name: "uninitialized_aws_with_limit", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS", Limit: 10}},
		{name: "uninitialized_azure_with_next_token", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE", NextToken: "tok123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ListTargets(tt.req)
			require.Error(t, err, "expected error for case %q, got nil (resp=%v)", tt.name, resp)
		})
	}
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — positive cases
// ---------------------------------------------------------------------------

// TestListTargets_Success_AWS verifies a well-formed 200 response for AWS CSP is decoded correctly.
func TestListTargets_Success_AWS(t *testing.T) {
	responseJSON := `{
		"response": [
			{
				"workspaceId": "ws-001",
				"workspaceName": "My AWS Account",
				"roleInfo": {"id": "role-1", "name": "Admin"},
				"organizationId": "org-123",
				"workspaceType": "ACCOUNT"
			}
		],
		"total": 1,
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

	svc := setupCloudConsoleService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, resp.Total)
	require.Len(t, resp.Response, 1)
	target := resp.Response[0]
	require.Equal(t, "ws-001", target.WorkspaceID)
	require.Equal(t, "My AWS Account", target.WorkspaceName)
	require.Equal(t, "org-123", target.OrganizationID)
	require.Equal(t, "ACCOUNT", target.WorkspaceType)
}

// TestListTargets_Success_MultipleTargets verifies multiple targets are decoded correctly.
func TestListTargets_Success_MultipleTargets(t *testing.T) {
	responseJSON := `{
		"response": [
			{"workspaceId": "ws-001", "workspaceName": "Account A", "role": {"id": "r-1", "name": "Admin"}, "workspaceType": "ACCOUNT"},
			{"workspaceId": "ws-002", "workspaceName": "Account B", "role": {"id": "r-2", "name": "Reader"}, "workspaceType": "ACCOUNT"}
		],
		"total": 2
	}`

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 2, resp.Total)
	require.Len(t, resp.Response, 2)
}

// TestListTargets_EmptyResponse verifies an empty targets list is handled without error.
func TestListTargets_EmptyResponse(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 0}`,
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 0, resp.Total)
	require.Empty(t, resp.Response)
}

// ---------------------------------------------------------------------------
// Mock HTTP server tests — URL path verification
// ---------------------------------------------------------------------------

// TestListTargets_URLPath verifies the exact eligibility path is used for each CSP,
// and that the path never includes /groups (which belongs to entragroups).
func TestListTargets_URLPath(t *testing.T) {
	tests := []struct {
		inputCSP     string
		expectedPath string
	}{
		{inputCSP: "AWS", expectedPath: "/api/access/AWS/eligibility"},
		{inputCSP: "aws", expectedPath: "/api/access/AWS/eligibility"},
		{inputCSP: "AZURE", expectedPath: "/api/access/AZURE/eligibility"},
		{inputCSP: "azure", expectedPath: "/api/access/AZURE/eligibility"},
		{inputCSP: "GCP", expectedPath: "/api/access/GCP/eligibility"},
		{inputCSP: "gcp", expectedPath: "/api/access/GCP/eligibility"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("csp_"+tt.inputCSP, func(t *testing.T) {
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

			svc := setupCloudConsoleService(client)
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: tt.inputCSP})

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, capturedPath)
			require.NotContains(t, capturedPath, "/groups")
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

	svc := setupCloudConsoleService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:         "AWS",
		WorkspaceID: "ws-filter-123",
	})

	require.NoError(t, err)
	require.Contains(t, capturedQuery, "workspaceId=ws-filter-123")
}

// TestListTargets_Pagination verifies limit and nextToken are forwarded as query params
// and that the response nextToken is read correctly.
func TestListTargets_Pagination(t *testing.T) {
	responseJSON := `{"response": [], "total": 50, "nextToken": "next-page-token"}`

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

	svc := setupCloudConsoleService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       "GCP",
		Limit:     10,
		NextToken: "prev-token",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "next-page-token", resp.NextToken)
	require.Contains(t, capturedQuery, "limit=10")
	require.Contains(t, capturedQuery, "nextToken=prev-token")
}

// TestListTargets_WorkspaceID_NotSentWhenEmpty verifies workspaceId is omitted
// from the query when it is not provided (no stray empty query params).
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

	svc := setupCloudConsoleService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

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
			ResponseBody: `{"message": "Bad Request", "description": "invalid parameters"}`,
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

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

	svc := setupCloudConsoleService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

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

	svc := setupCloudConsoleService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

// TestListTargets_ErrorPropagation verifies all common HTTP error codes are propagated.
// This uses the shared helper which runs 400, 404, 500 as sub-tests automatically.
func TestListTargets_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupCloudConsoleService(client)
		_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})
		return err
	})
}

// TestListTargets_UnsupportedCSP_ErrorMessage verifies the error message names the invalid CSP.
func TestListTargets_UnsupportedCSP_ErrorMessage(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	unsupportedCSPs := []string{"ibm", "IBM", "oracle", "alicloud"}

	for _, csp := range unsupportedCSPs {
		csp := csp
		t.Run("csp_"+csp, func(t *testing.T) {
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: csp})
			require.Error(t, err)
			require.Contains(t, err.Error(), csp)
		})
	}
}

// TestListTargets_AllSupportedCSPs_HitCorrectPath verifies AWS, AZURE and GCP each
// produce a distinct and correct URL path when the service is initialized.
func TestListTargets_AllSupportedCSPs_HitCorrectPath(t *testing.T) {
	tests := []struct {
		csp          string
		expectedPath string
	}{
		{"AWS", "/api/access/AWS/eligibility"},
		{"AZURE", "/api/access/AZURE/eligibility"},
		{"GCP", "/api/access/GCP/eligibility"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.csp, func(t *testing.T) {
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

			svc := setupCloudConsoleService(client)
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: tt.csp})

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, capturedPath)
			// Must never hit the entragroups endpoint
			require.False(t, strings.HasSuffix(capturedPath, "/groups"))
		})
	}
}

// ---------------------------------------------------------------------------
// Elevate — validation tests (no HTTP call)
// ---------------------------------------------------------------------------

func TestElevate_validation_nil_request(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")
}

func TestElevate_validation_empty_csp(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		WorkspaceID: "ws-1",
		RoleID:      "role-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "csp")
}

func TestElevate_validation_missing_workspace_id(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:    "AWS",
		RoleID: "test-role-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "workspaceId")
}

func TestElevate_validation_missing_role(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "roleId")
}

func TestElevate_validation_uninitialized_service(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleID:      "test-role-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not initialized")
}

// ---------------------------------------------------------------------------
// Elevate — success tests
// ---------------------------------------------------------------------------

func TestElevate_Success_AWS(t *testing.T) {
	// accessCredentials is a double-encoded JSON string (escaped within the outer JSON).
	responseJSON := "{\"response\":{\"organizationId\":\"test-org\",\"csp\":\"AWS\",\"results\":[{\"workspaceId\":\"test-workspace-id\",\"roleId\":\"test-role-id\",\"sessionId\":\"test-session-id\",\"accessCredentials\":\"{\\\"aws_access_key\\\":\\\"test-access-key\\\",\\\"aws_secret_access_key\\\":\\\"test-secret-key\\\",\\\"aws_session_token\\\":\\\"test-session-token\\\"}\"}]}}"

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	resp, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleID:      "test-role-id",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "test-org", resp.Response.OrganizationID)
	require.Equal(t, "AWS", resp.Response.CSP)
	require.Len(t, resp.Response.Results, 1)
	result := resp.Response.Results[0]
	require.Equal(t, "test-workspace-id", result.WorkspaceID)
	require.Equal(t, "test-role-id", result.RoleID)
	require.Equal(t, "test-session-id", result.SessionID)
	require.NotEmpty(t, result.AccessCredentials)
}

func TestElevate_Success_NotEligible(t *testing.T) {
	responseJSON := `{
		"response": {
			"organizationId": "test-org",
			"csp": "AWS",
			"results": [
				{
					"workspaceId": "test-workspace-id",
					"roleId": "test-role-id",
					"errorInfo": {
						"code": "CA1009",
						"message": "We can't connect you to the cloud console",
						"description": "It looks like your user is not eligible to access this target",
						"link": "https://docs.cyberark.com/sca/latest/en/Content/Troubleshooting/sca_error-codes.htm"
					}
				}
			]
		}
	}`

	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	resp, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleID:      "test-role-id",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Response.Results, 1)
	result := resp.Response.Results[0]
	require.Equal(t, "test-workspace-id", result.WorkspaceID)
	require.Empty(t, result.AccessCredentials)
	require.NotNil(t, result.ErrorInfo)
	require.Equal(t, "CA1009", result.ErrorInfo.Code)
	require.Equal(t, "We can't connect you to the cloud console", result.ErrorInfo.Message)
	require.NotEmpty(t, result.ErrorInfo.Description)
	require.NotEmpty(t, result.ErrorInfo.Link)
}

// ---------------------------------------------------------------------------
// Elevate — URL and method verification
// ---------------------------------------------------------------------------

func TestElevate_URL_Method(t *testing.T) {
	var capturedPath, capturedMethod string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":{"organizationId":"","csp":"AWS","results":[]}}`,
			OnRequest: func(r *http.Request) {
				capturedPath = r.URL.Path
				capturedMethod = r.Method
			},
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "ws-1",
		RoleID:      "role-1",
	})

	require.NoError(t, err)
	require.Equal(t, "/api/access/elevate", capturedPath)
	require.Equal(t, http.MethodPost, capturedMethod)
}

// ---------------------------------------------------------------------------
// Elevate — request body verification
// ---------------------------------------------------------------------------

func TestElevate_RequestBody(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":{"organizationId":"","csp":"AWS","results":[]}}`,
			OnRequest: func(r *http.Request) {
				capturedBody = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleID:      "test-role-id",
	})

	require.NoError(t, err)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AWS", body["csp"])
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 1)
	target := targets[0].(map[string]interface{})
	require.Equal(t, "test-workspace-id", target["workspaceId"])
	require.Equal(t, "test-role-id", target["roleId"])
}

// ---------------------------------------------------------------------------
// Elevate — HTTP error tests
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

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleID: "role-1",
	})

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

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleID: "role-1",
	})

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

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleID: "role-1",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestElevate_CommaSeparatedRoleIDs_AZURE(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":{"organizationId":"test-org","csp":"AZURE","results":[]}}`,
			OnRequest: func(r *http.Request) {
				capturedBody = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:            "AZURE",
		WorkspaceID:    "ws-1",
		RoleID:         "role-a,role-b,role-c",
		OrganizationID: "org-1",
	})

	require.NoError(t, err)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 3)
	for i, expectedRole := range []string{"role-a", "role-b", "role-c"} {
		target := targets[i].(map[string]interface{})
		require.Equal(t, "ws-1", target["workspaceId"])
		require.Equal(t, expectedRole, target["roleId"])
	}
}

func TestElevate_CommaSeparatedRoleIDs_AWS(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":{"organizationId":"","csp":"AWS","results":[]}}`,
			OnRequest: func(r *http.Request) {
				capturedBody = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "aws-account-1",
		RoleID:      "role-a,role-b,role-c",
	})

	require.NoError(t, err)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AWS", body["csp"])
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 3)
	for i, expectedRole := range []string{"role-a", "role-b", "role-c"} {
		target := targets[i].(map[string]interface{})
		require.Equal(t, "aws-account-1", target["workspaceId"])
		require.Equal(t, expectedRole, target["roleId"])
	}
}

func TestElevate_ExceedsMaxRoleIDs(t *testing.T) {
	svc := &IdsecSCACloudConsoleService{}
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:         "AZURE",
		WorkspaceID: "ws-1",
		RoleID:      "r1,r2,r3,r4,r5,r6",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum")
}

func TestElevate_RequestBody_WithOrganizationID(t *testing.T) {
	var capturedBody []byte
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response":{"organizationId":"test-org","csp":"AZURE","results":[]}}`,
			OnRequest: func(r *http.Request) {
				capturedBody = make([]byte, r.ContentLength)
				_, _ = r.Body.Read(capturedBody)
			},
		},
	})
	defer cleanup()

	svc := setupCloudConsoleService(client)
	_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
		CSP:            "AZURE",
		WorkspaceID:    "test-workspace-id",
		RoleID:         "test-role-id",
		OrganizationID: "test-org-id",
	})

	require.NoError(t, err)
	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(capturedBody, &body))
	require.Equal(t, "AZURE", body["csp"])
	require.Equal(t, "test-org-id", body["organizationId"])
	targets, ok := body["targets"].([]interface{})
	require.True(t, ok)
	require.Len(t, targets, 1)
	target := targets[0].(map[string]interface{})
	require.Equal(t, "test-workspace-id", target["workspaceId"])
	require.Equal(t, "test-role-id", target["roleId"])
}

func TestElevate_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupCloudConsoleService(client)
		_, err := svc.Elevate(&cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest{
			CSP: "AWS", WorkspaceID: "ws-1", RoleID: "role-1",
		})
		return err
	})
}
