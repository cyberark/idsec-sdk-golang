package cloudaccess

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
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// setupCloudAccessService creates an IdsecSCACloudAccessService with the given mock ISP client injected.
func setupCloudAccessService(client *isp.IdsecISPServiceClient) *IdsecSCACloudAccessService {
	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecSCACloudAccessService{
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
	svc := &IdsecSCACloudAccessService{}
	tests := []struct {
		name string
		req  *scamodels.IdsecSCAListTargetsRequest
	}{
		{name: "nil_request", req: nil},
		{name: "empty_csp", req: &scamodels.IdsecSCAListTargetsRequest{}},
		{name: "unsupported_csp_ibm", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "ibm"}},
		{name: "unsupported_csp_oracle", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "oracle"}},
		{name: "unsupported_csp_mixed_case", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "Ibm"}},
		{name: "csp_and_all", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS", All: true}},
		// All supported CSPs still fail here because the service is uninitialized (no HTTP client).
		{name: "uninitialized_aws", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"}},
		{name: "uninitialized_azure", req: &scamodels.IdsecSCAListTargetsRequest{CSP: "AZURE"}},
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

func TestListTargets_CSPAndAll(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS", All: true})

	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "choose either csp or all")
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

	svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 0, resp.Total)
	require.Empty(t, resp.Response)
}

func TestListTargets_AllFlag_AggregatesAWSAndAzure(t *testing.T) {
	var capturedPaths []string
	var capturedQueries []string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/api/access/AWS/eligibility" && r.URL.Query().Get("nextToken") == ""
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "aws-001", "workspaceName": "AWS Account", "workspaceType": "ACCOUNT"}],
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
				return r.URL.Path == "/api/access/AWS/eligibility" && r.URL.Query().Get("nextToken") == "aws-page-2"
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "aws-002", "workspaceName": "AWS Account 2", "workspaceType": "ACCOUNT"}],
				"total": 2
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.URL.Path == "/api/access/AZURE/eligibility" && r.URL.Query().Get("nextToken") == ""
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "azure-001", "workspaceName": "Azure Subscription", "workspaceType": "SUBSCRIPTION"}],
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
				return r.URL.Path == "/api/access/AZURE/eligibility" && r.URL.Query().Get("nextToken") == "azure-page-2"
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"response": [{"workspaceId": "azure-002", "workspaceName": "Azure Subscription 2", "workspaceType": "SUBSCRIPTION"}],
				"total": 2
			}`,
			OnRequest: func(r *http.Request) {
				capturedPaths = append(capturedPaths, r.URL.Path)
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
	})
	defer cleanup()

	svc := setupCloudAccessService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{All: true})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 4, resp.Total)
	require.Empty(t, resp.Response)
	require.Len(t, resp.Responses, 2)
	require.Len(t, resp.Responses["aws"].Response, 2)
	require.Equal(t, 2, resp.Responses["aws"].Total)
	require.Len(t, resp.Responses["azure"].Response, 2)
	require.Equal(t, 2, resp.Responses["azure"].Total)
	require.Empty(t, resp.NextToken)
	require.Empty(t, resp.Errors)
	require.ElementsMatch(t, []string{"/api/access/AWS/eligibility", "/api/access/AWS/eligibility", "/api/access/AZURE/eligibility", "/api/access/AZURE/eligibility"}, capturedPaths)
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
				"response": [{"workspaceId": "azure-001", "workspaceName": "Azure Subscription", "workspaceType": "SUBSCRIPTION"}],
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
				"response": [{"workspaceId": "aws-001", "workspaceName": "AWS Account", "workspaceType": "ACCOUNT"}],
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
					Matcher:      func(r *http.Request) bool { return r.URL.Path == "/api/access/AWS/eligibility" },
					StatusCode:   tt.awsStatus,
					ResponseBody: tt.awsResponseBody,
				},
				{
					Matcher:      func(r *http.Request) bool { return r.URL.Path == "/api/access/AZURE/eligibility" },
					StatusCode:   tt.azureStatus,
					ResponseBody: tt.azureResponseBody,
				},
			})
			defer cleanup()

			svc := setupCloudAccessService(client)
			resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{})

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

	svc := setupCloudAccessService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{})

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

// ---------------------------------------------------------------------------
// Mock HTTP server tests — URL path verification
// ---------------------------------------------------------------------------

// TestListTargets_URLPath verifies the exact eligibility path is used for each CSP,
// and that the path never includes /groups (which belongs to groupaccess).
func TestListTargets_URLPath(t *testing.T) {
	tests := []struct {
		inputCSP     string
		expectedPath string
	}{
		{inputCSP: "AWS", expectedPath: "/api/access/AWS/eligibility"},
		{inputCSP: "aws", expectedPath: "/api/access/AWS/eligibility"},
		{inputCSP: "AZURE", expectedPath: "/api/access/AZURE/eligibility"},
		{inputCSP: "azure", expectedPath: "/api/access/AZURE/eligibility"},
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

			svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:         "AWS",
		WorkspaceID: "ws-filter-123",
	})

	require.NoError(t, err)
	require.Contains(t, capturedQuery, "workspaceId=ws-filter-123")
}

// TestListTargets_Pagination verifies limit and nextToken are forwarded as query params
// and that single-CSP list-targets follows response nextToken values.
func TestListTargets_Pagination(t *testing.T) {
	var capturedQueries []string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.URL.Query().Get("nextToken") == "prev-token" },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 50, "nextToken": "next-page-token"}`,
			OnRequest: func(r *http.Request) {
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
		{
			Matcher:      func(r *http.Request) bool { return r.URL.Query().Get("nextToken") == "next-page-token" },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"response": [], "total": 50}`,
			OnRequest: func(r *http.Request) {
				capturedQueries = append(capturedQueries, r.URL.RawQuery)
			},
		},
	})
	defer cleanup()

	svc := setupCloudAccessService(client)
	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       "AWS",
		Limit:     10,
		NextToken: "prev-token",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 50, resp.Total)
	require.Empty(t, resp.NextToken)
	require.Len(t, capturedQueries, 2)
	require.Contains(t, capturedQueries[0], "limit=10")
	require.Contains(t, capturedQueries[0], "nextToken=prev-token")
	require.Contains(t, capturedQueries[1], "limit=10")
	require.Contains(t, capturedQueries[1], "nextToken=next-page-token")
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

	svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
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

	svc := setupCloudAccessService(client)
	_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

// TestListTargets_ErrorPropagation verifies all common HTTP error codes are propagated.
// This uses the shared helper which runs 400, 404, 500 as sub-tests automatically.
func TestListTargets_ErrorPropagation(t *testing.T) {
	scainternal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		svc := setupCloudAccessService(client)
		_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})
		return err
	})
}

// TestListTargets_UnsupportedCSP_ErrorMessage verifies the error message names the invalid CSP.
func TestListTargets_UnsupportedCSP_ErrorMessage(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
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

// TestListTargets_AllSupportedCSPs_HitCorrectPath verifies AWS and AZURE each
// produce a distinct and correct URL path when the service is initialized.
func TestListTargets_AllSupportedCSPs_HitCorrectPath(t *testing.T) {
	tests := []struct {
		csp          string
		expectedPath string
	}{
		{"AWS", "/api/access/AWS/eligibility"},
		{"AZURE", "/api/access/AZURE/eligibility"},
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

			svc := setupCloudAccessService(client)
			_, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: tt.csp})

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, capturedPath)
			// Must never hit the groupaccess endpoint
			require.False(t, strings.HasSuffix(capturedPath, "/groups"))
		})
	}
}

// ---------------------------------------------------------------------------
// Elevate — validation tests (no HTTP call)
// ---------------------------------------------------------------------------

func TestElevate_validation_nil_request(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")
}

func TestElevate_validation_empty_csp(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		WorkspaceID: "ws-1",
		RoleIDs:     "role-1",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "csp")
}

func TestElevate_validation_missing_workspace_id(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:     "AWS",
		RoleIDs: "test-role-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "workspaceId")
}

func TestElevate_validation_missing_role(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "roleIds")
}

func TestElevate_validation_uninitialized_service(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleIDs:     "test-role-id",
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

	svc := setupCloudAccessService(client)
	resp, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleIDs:     "test-role-id",
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

	svc := setupCloudAccessService(client)
	resp, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleIDs:     "test-role-id",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "ws-1",
		RoleIDs:     "role-1",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "test-workspace-id",
		RoleIDs:     "test-role-id",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleIDs: "role-1",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleIDs: "role-1",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP: "AWS", WorkspaceID: "ws-1", RoleIDs: "role-1",
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:            "AZURE",
		WorkspaceID:    "ws-1",
		RoleIDs:        "role-a,role-b,role-c",
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

func TestElevate_CommaSeparatedRoleIDs_AWS_ReturnsError(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AWS",
		WorkspaceID: "aws-account-1",
		RoleIDs:     "role-a,role-b,role-c",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum 1 role IDs allowed for AWS")
}

func TestElevate_ExceedsMaxRoleIDs_AZURE(t *testing.T) {
	svc := &IdsecSCACloudAccessService{}
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:         "AZURE",
		WorkspaceID: "ws-1",
		RoleIDs:     "r1,r2,r3,r4,r5,r6",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "maximum 5 role IDs allowed for AZURE")
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

	svc := setupCloudAccessService(client)
	_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:            "AZURE",
		WorkspaceID:    "test-workspace-id",
		RoleIDs:        "test-role-id",
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
		svc := setupCloudAccessService(client)
		_, err := svc.Elevate(&cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
			CSP: "AWS", WorkspaceID: "ws-1", RoleIDs: "role-1",
		})
		return err
	})
}
