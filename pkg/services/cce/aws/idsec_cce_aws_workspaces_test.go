package aws

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestWorkspaces_Success(t *testing.T) {
	responseJSON := `{
		"workspaces": [
			{
				"key": "workspace-123",
				"data": {
					"id": "workspace-123",
					"platform_id": "123456789012",
					"display_name": "My AWS Account",
					"type": "aws_account",
					"platform_type": "AWS",
					"onboarding_type": "programmatic",
					"status": "Completely added",
					"services": [
						{
							"name": "dpa",
							"version": "1.0.0",
							"service_status": "Completely added"
						}
					],
					"organization_id": "org-456",
					"organization_name": "My Organization"
				},
				"leaf": true,
				"path": "/root/workspace-123",
				"parent_id": "org-456"
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 1
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Contains(t, r.URL.Path, "/api/aws/workspaces")
				// Verify query parameters
				query := r.URL.Query()
				require.Equal(t, "true", query.Get("include_suspended"))
				require.Equal(t, "2", query.Get("page"))
				require.Equal(t, "100", query.Get("page_size"))
				require.Equal(t, "org-456", query.Get("parent_id"))
				require.Equal(t, []string{"dpa", "cds"}, query["services"])
				require.Equal(t, "Completely added", query.Get("workspace_status"))
				require.Equal(t, "aws_account", query.Get("workspace_type"))
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the Workspaces function with all query parameters
	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
		IncludeSuspended: true,
		Page:             2,
		PageSize:         100,
		ParentID:         "org-456",
		Services:         "dpa,cds",
		WorkspaceStatus:  "Completely added",
		WorkspaceType:    "aws_account",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)

	// Build expected struct
	expected := &awsmodels.TfIdsecCCEAWSWorkspaces{
		Workspaces: []ccemodels.TfIdsecCCEWorkspace{
			{
				Key: "workspace-123",
				Data: ccemodels.TfIdsecCCEWorkspaceData{
					ID:             "workspace-123",
					PlatformID:     "123456789012",
					DisplayName:    "My AWS Account",
					Type:           "aws_account",
					PlatformType:   "AWS",
					OnboardingType: ccemodels.Programmatic,
					Status:         ccemodels.CompletelyAdded,
					Services: []ccemodels.IdsecCCEServiceDto{
						{
							Name:          "dpa",
							Version:       "1.0.0",
							ServiceStatus: ccemodels.CompletelyAdded,
						},
					},
					OrganizationID:   "org-456",
					OrganizationName: "My Organization",
				},
				Leaf:     true,
				Path:     "/root/workspace-123",
				ParentID: "org-456",
			},
		},
		Page: ccemodels.IdsecCCEPageOutput{
			PageNumber:   1,
			PageSize:     1000,
			IsLastPage:   true,
			TotalRecords: 1,
		},
	}

	// Compare structs
	require.Equal(t, expected, result)
}

func TestWorkspaces_MinimalInput(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Contains(t, r.URL.Path, "/api/aws/workspaces")
				// Verify no query parameters are set when using empty input
				query := r.URL.Query()
				require.Empty(t, query.Get("include_suspended"))
				require.Empty(t, query.Get("page"))
				require.Empty(t, query.Get("page_size"))
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the Workspaces function with minimal input
	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Workspaces)
	require.Equal(t, 1, result.Page.PageNumber)
	require.Equal(t, 1000, result.Page.PageSize)
	require.True(t, result.Page.IsLastPage)
	require.Equal(t, 0, result.Page.TotalRecords)
}

func TestWorkspaces_WithIncludeSuspended(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				query := r.URL.Query()
				require.Equal(t, "true", query.Get("include_suspended"))
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
		IncludeSuspended: true,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestWorkspaces_WithPagination(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 3,
			"page_size": 50,
			"is_last_page": false,
			"total_records": 250
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				query := r.URL.Query()
				require.Equal(t, "3", query.Get("page"))
				require.Equal(t, "50", query.Get("page_size"))
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
		Page:     3,
		PageSize: 50,
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 3, result.Page.PageNumber)
	require.Equal(t, 50, result.Page.PageSize)
	require.False(t, result.Page.IsLastPage)
	require.Equal(t, 250, result.Page.TotalRecords)
}

func TestWorkspaces_WithParentID(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				query := r.URL.Query()
				require.Equal(t, "parent-org-789", query.Get("parent_id"))
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
		ParentID: "parent-org-789",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestWorkspaces_WithServicesFilter(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				query := r.URL.Query()
				require.Equal(t, []string{"dpa", "sca", "cds"}, query["services"])
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
		Services: "dpa,sca,cds",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestWorkspaces_WithWorkspaceStatusFilter(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	testCases := []struct {
		name            string
		workspaceStatus string
	}{
		{
			name:            "CompletelyAdded",
			workspaceStatus: "Completely added",
		},
		{
			name:            "FailedToAdd",
			workspaceStatus: "Failed to add",
		},
		{
			name:            "PartiallyAdded",
			workspaceStatus: "Partially added",
		},
		{
			name:            "MultipleStatuses",
			workspaceStatus: "Completely added,Failed to add,Partially added",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return true },
					StatusCode:   http.StatusOK,
					ResponseBody: responseJSON,
					OnRequest: func(r *http.Request) {
						query := r.URL.Query()
						require.Equal(t, tc.workspaceStatus, query.Get("workspace_status"))
					},
				},
			})
			defer cleanup()

			service := setupAWSService(client)

			result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
				WorkspaceStatus: tc.workspaceStatus,
			})

			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}

func TestWorkspaces_WithWorkspaceTypeFilter(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	testCases := []struct {
		name          string
		workspaceType string
	}{
		{
			name:          "AWSOrganization",
			workspaceType: "aws_organization",
		},
		{
			name:          "AWSAccount",
			workspaceType: "aws_account",
		},
		{
			name:          "AzureOrganization",
			workspaceType: "azure_organization",
		},
		{
			name:          "AzureSubscription",
			workspaceType: "azure_subscription",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return true },
					StatusCode:   http.StatusOK,
					ResponseBody: responseJSON,
					OnRequest: func(r *http.Request) {
						query := r.URL.Query()
						require.Equal(t, tc.workspaceType, query.Get("workspace_type"))
					},
				},
			})
			defer cleanup()

			service := setupAWSService(client)

			result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{
				WorkspaceType: tc.workspaceType,
			})

			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}

func TestWorkspaces_CombinedFilters(t *testing.T) {
	responseJSON := `{
		"workspaces": [],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 0
		}
	}`

	testCases := []struct {
		name  string
		input *awsmodels.TfIdsecCCEAWSGetWorkspaces
	}{
		{
			name: "ServicesAndStatus",
			input: &awsmodels.TfIdsecCCEAWSGetWorkspaces{
				Services:        "dpa",
				WorkspaceStatus: "Completely added",
			},
		},
		{
			name: "ParentAndType",
			input: &awsmodels.TfIdsecCCEAWSGetWorkspaces{
				ParentID:      "org-123",
				WorkspaceType: "aws_account",
			},
		},
		{
			name: "PaginationAndFilters",
			input: &awsmodels.TfIdsecCCEAWSGetWorkspaces{
				Page:            2,
				PageSize:        25,
				Services:        "dpa,cds",
				WorkspaceStatus: "Completely added",
			},
		},
		{
			name: "SuspendedAndParent",
			input: &awsmodels.TfIdsecCCEAWSGetWorkspaces{
				IncludeSuspended: true,
				ParentID:         "root-456",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return true },
					StatusCode:   http.StatusOK,
					ResponseBody: responseJSON,
					OnRequest: func(r *http.Request) {
						query := r.URL.Query()
						// Verify that the expected parameters are present
						if tc.input.IncludeSuspended {
							require.Equal(t, "true", query.Get("include_suspended"))
						}
						if tc.input.Page > 0 {
							require.NotEmpty(t, query.Get("page"))
						}
						if tc.input.PageSize > 0 {
							require.NotEmpty(t, query.Get("page_size"))
						}
						if tc.input.ParentID != "" {
							require.Equal(t, tc.input.ParentID, query.Get("parent_id"))
						}
						if tc.input.Services != "" {
							expectedServices := strings.Split(tc.input.Services, ",")
							for i, s := range expectedServices {
								expectedServices[i] = strings.TrimSpace(s)
							}
							require.Equal(t, expectedServices, query["services"])
						}
						if tc.input.WorkspaceStatus != "" {
							require.Equal(t, tc.input.WorkspaceStatus, query.Get("workspace_status"))
						}
						if tc.input.WorkspaceType != "" {
							require.Equal(t, tc.input.WorkspaceType, query.Get("workspace_type"))
						}
					},
				},
			})
			defer cleanup()

			service := setupAWSService(client)

			result, err := service.tfInternalWorkspaces(tc.input)

			require.NoError(t, err)
			require.NotNil(t, result)
		})
	}
}

func TestWorkspaces_MultipleWorkspaces(t *testing.T) {
	responseJSON := `{
		"workspaces": [
			{
				"key": "workspace-1",
				"data": {
					"id": "ws-id-1",
					"platform_id": "123456789012",
					"display_name": "AWS Account 1",
					"type": "aws_account",
					"platform_type": "AWS",
					"onboarding_type": "programmatic",
					"status": "Completely added"
				},
				"leaf": true,
				"parent_id": "org-123"
			},
			{
				"key": "workspace-2",
				"data": {
					"id": "ws-id-2",
					"platform_id": "987654321098",
					"display_name": "AWS Account 2",
					"type": "aws_account",
					"platform_type": "AWS",
					"onboarding_type": "standard",
					"status": "Partially added"
				},
				"leaf": true,
				"parent_id": "org-123"
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 1000,
			"is_last_page": true,
			"total_records": 2
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	result, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Workspaces, 2)
	require.Equal(t, "workspace-1", result.Workspaces[0].Key)
	require.Equal(t, "workspace-2", result.Workspaces[1].Key)
	require.Equal(t, "AWS Account 1", result.Workspaces[0].Data.DisplayName)
	require.Equal(t, "AWS Account 2", result.Workspaces[1].Data.DisplayName)
	require.Equal(t, 2, result.Page.TotalRecords)
}

func TestWorkspaces_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.tfInternalWorkspaces(&awsmodels.TfIdsecCCEAWSGetWorkspaces{})
		return err
	})
}
