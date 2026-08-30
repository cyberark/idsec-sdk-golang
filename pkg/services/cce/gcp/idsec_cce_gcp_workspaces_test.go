package gcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfWorkspaces_SinglePage(t *testing.T) {
	// Mock response for GET /api/gcp/workspaces (single page)
	responseJSON := `{
		"workspaces": [
			{
				"key": "org-123",
				"data": {
					"id": "org-123",
					"platform_id": "123456789012",
					"display_name": "Test GCP Organization",
					"type": "gcp_organization",
					"platform_type": "GCP",
					"status": "Completely added"
				},
				"leaf": false,
				"parent_id": ""
			},
			{
				"key": "project-456",
				"data": {
					"id": "project-456",
					"platform_id": "my-gcp-project",
					"display_name": "Test Project",
					"type": "gcp_project",
					"platform_type": "GCP",
					"status": "Completely added"
				},
				"leaf": true,
				"parent_id": "org-123"
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 100,
			"is_last_page": true,
			"total_records": 2
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/workspaces"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 2)
	require.Equal(t, "org-123", result.Workspaces[0].Key)
	require.Equal(t, "project-456", result.Workspaces[1].Key)
}

func TestTfWorkspaces_MultiplePagesSuccess(t *testing.T) {
	// Mock response for page 1
	page1ResponseJSON := `{
		"workspaces": [
			{
				"key": "org-1",
				"data": {
					"id": "org-1",
					"platform_id": "111111111111",
					"display_name": "Org 1",
					"type": "gcp_organization",
					"platform_type": "GCP",
					"status": "Completely added"
				},
				"leaf": false,
				"parent_id": ""
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 100,
			"is_last_page": false,
			"total_records": 2
		}
	}`

	// Mock response for page 2
	page2ResponseJSON := `{
		"workspaces": [
			{
				"key": "org-2",
				"data": {
					"id": "org-2",
					"platform_id": "222222222222",
					"display_name": "Org 2",
					"type": "gcp_organization",
					"platform_type": "GCP",
					"status": "Completely added"
				},
				"leaf": false,
				"parent_id": ""
			}
		],
		"page": {
			"page_number": 2,
			"page_size": 100,
			"is_last_page": true,
			"total_records": 2
		}
	}`

	pageRequestCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && r.URL.Path == "/api/gcp/workspaces" {
					pageRequestCount++
					// Return page 1 on first request
					if pageRequestCount == 1 {
						return true
					}
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: page1ResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Return page 2 on second and subsequent requests
				if r.Method == "GET" && r.URL.Path == "/api/gcp/workspaces" && pageRequestCount >= 2 {
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: page2ResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 2, "Should have collected workspaces from both pages")
	require.Equal(t, "org-1", result.Workspaces[0].Key)
	require.Equal(t, "org-2", result.Workspaces[1].Key)
	require.Equal(t, 2, pageRequestCount, "Should have made 2 page requests")
}

func TestTfWorkspaces_WithFilters(t *testing.T) {
	responseJSON := `{
		"workspaces": [
			{
				"key": "project-456",
				"data": {
					"id": "project-456",
					"platform_id": "my-gcp-project",
					"display_name": "Test Project",
					"type": "gcp_project",
					"platform_type": "GCP",
					"status": "Completely added"
				},
				"leaf": true,
				"parent_id": "org-123"
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 100,
			"is_last_page": true,
			"total_records": 1
		}
	}`

	var capturedRequest *http.Request
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && r.URL.Path == "/api/gcp/workspaces" {
					capturedRequest = r
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfWorkspaces with filters
	result, err := service.TfWorkspaces(&gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{
		ParentID:               "org-123",
		Services:               "dpa,sca",
		WorkspaceStatus:        "Completely added",
		WorkspaceType:          "gcp_project",
		IncludeEmptyWorkspaces: true,
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 1)

	// Verify query parameters were set correctly
	require.NotNil(t, capturedRequest)
	query := capturedRequest.URL.Query()
	require.Equal(t, "org-123", query.Get("parent_id"))
	require.Equal(t, "Completely added", query.Get("workspace_status"))
	require.Equal(t, "gcp_project", query.Get("workspace_type"))
	require.Equal(t, "true", query.Get("include_empty_workspaces"))
	// Services should be split into multiple params
	require.Contains(t, query["services"], "dpa")
	require.Contains(t, query["services"], "sca")
}

func TestTfWorkspaces_EmptyResult(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 100,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/workspaces"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 0)
}

func TestTfWorkspaces_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfWorkspaces(&gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{})
		return err
	})
}
