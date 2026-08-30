package gcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfProject_Success(t *testing.T) {
	responseJSON := `{
		"id": "project-123",
		"projectId": "gcp-project-12345",
		"onboardingType": "terraform_provider",
		"region": "us-central1",
		"displayName": "Test Project",
		"status": "Completely added",
		"services": ["dpa", "sca"],
		"servicesData": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"parameters": {
			"sca": {
				"ssoEnabled": true,
				"ssoRegion": "us-central1"
			}
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfProject
	result, err := service.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{
		ID: "project-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "project-123", result.ID)
	require.Equal(t, "gcp-project-12345", result.ProjectID)
	require.Equal(t, "terraform_provider", result.OnboardingType)
	require.Equal(t, "us-central1", result.Region)
	require.Equal(t, "Test Project", result.DisplayName)
	require.Equal(t, "Completely added", result.Status)
	require.Equal(t, []string{"dpa", "sca"}, result.Services)

	require.Len(t, result.ServicesData, 2)
	require.Equal(t, "dpa", result.ServicesData[0].Name)
	require.Equal(t, "Completely added", result.ServicesData[0].Status)
	require.Equal(t, "sca", result.ServicesData[1].Name)
	require.Equal(t, "Completely added", result.ServicesData[1].Status)

	require.NotNil(t, result.Parameters, "Parameters should not be nil")
	require.Contains(t, result.Parameters, "sca", "Parameters should contain 'sca' key")
	scaParams, ok := result.Parameters["sca"]
	require.True(t, ok, "Should be able to get 'sca' parameters")
	require.Equal(t, true, scaParams["ssoEnabled"])
	require.Equal(t, "us-central1", scaParams["ssoRegion"])
}

func TestTfProject_WithOrganization(t *testing.T) {
	responseJSON := `{
		"id": "project-123",
		"projectId": "gcp-project-12345",
		"onboardingType": "standard",
		"status": "Completely added",
		"organizationId": "org-456",
		"organizationName": "Test Organization",
		"duplicatedServices": ["sca"]
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	result, err := service.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{
		ID: "project-123",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "org-456", result.OrganizationID)
	require.Equal(t, "Test Organization", result.OrganizationName)
	require.NotNil(t, result.DuplicatedServices)
	require.Equal(t, []string{"sca"}, *result.DuplicatedServices)
}

func TestProject_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{ID: "project-123"})
		return err
	})
}
