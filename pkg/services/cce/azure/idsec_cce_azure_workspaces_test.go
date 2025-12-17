package azure

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfWorkspaces_SinglePage(t *testing.T) {
	// Mock response for GET /api/azure/workspaces (single page)
	responseJSON := `{
		"workspaces": [
			{
				"key": "entra-123",
				"data": {
					"id": "entra-123",
					"platform_id": "12345678-1234-1234-1234-123456789012",
					"display_name": "Test Entra Tenant",
					"type": "azure_entra",
					"platform_type": "Azure",
					"status": "Completely added"
				},
				"leaf": false,
				"parent_id": ""
			},
			{
				"key": "subscription-456",
				"data": {
					"id": "subscription-456",
					"platform_id": "sub-12345678-1234-1234-1234-123456789012",
					"display_name": "Test Subscription",
					"type": "azure_subscription",
					"platform_type": "Azure",
					"status": "Completely added"
				},
				"leaf": true,
				"parent_id": "entra-123"
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
				return r.Method == "GET" && r.URL.Path == "/api/azure/workspaces"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 2)
	require.Equal(t, "entra-123", result.Workspaces[0].Key)
	require.Equal(t, "subscription-456", result.Workspaces[1].Key)
}

func TestTfWorkspaces_MultiplePagesSuccess(t *testing.T) {
	// Mock response for page 1
	page1ResponseJSON := `{
		"workspaces": [
			{
				"key": "entra-1",
				"data": {
					"id": "entra-1",
					"platform_id": "11111111-1111-1111-1111-111111111111",
					"display_name": "Entra 1",
					"type": "azure_entra",
					"platform_type": "Azure",
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
				"key": "entra-2",
				"data": {
					"id": "entra-2",
					"platform_id": "22222222-2222-2222-2222-222222222222",
					"display_name": "Entra 2",
					"type": "azure_entra",
					"platform_type": "Azure",
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
				if r.Method == "GET" && r.URL.Path == "/api/azure/workspaces" {
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
				if r.Method == "GET" && r.URL.Path == "/api/azure/workspaces" && pageRequestCount >= 2 {
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: page2ResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 2, "Should have collected workspaces from both pages")
	require.Equal(t, "entra-1", result.Workspaces[0].Key)
	require.Equal(t, "entra-2", result.Workspaces[1].Key)
	require.Equal(t, 2, pageRequestCount, "Should have made 2 page requests")
}

func TestTfWorkspaces_WithFilters(t *testing.T) {
	responseJSON := `{
		"workspaces": [
			{
				"key": "subscription-456",
				"data": {
					"id": "subscription-456",
					"platform_id": "sub-12345678-1234-1234-1234-123456789012",
					"display_name": "Test Subscription",
					"type": "azure_subscription",
					"platform_type": "Azure",
					"status": "Completely added"
				},
				"leaf": true,
				"parent_id": "entra-123"
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
				if r.Method == "GET" && r.URL.Path == "/api/azure/workspaces" {
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

	service := setupAzureService(client)

	// Call TfWorkspaces with filters
	result, err := service.TfWorkspaces(&azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{
		ParentID:        "entra-123",
		Services:        "dpa,sca",
		WorkspaceStatus: "Completely added",
		WorkspaceType:   "azure_subscription",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 1)

	// Verify query parameters were set correctly
	require.NotNil(t, capturedRequest)
	query := capturedRequest.URL.Query()
	require.Equal(t, "entra-123", query.Get("parent_id"))
	require.Equal(t, "Completely added", query.Get("workspace_status"))
	require.Equal(t, "azure_subscription", query.Get("workspace_type"))
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
				return r.Method == "GET" && r.URL.Path == "/api/azure/workspaces"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfWorkspaces
	result, err := service.TfWorkspaces(&azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 0)
}

func TestTfWorkspaces_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAzureService(client)
		_, err := service.TfWorkspaces(&azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform{})
		return err
	})
}
