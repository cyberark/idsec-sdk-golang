package gcp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfOrganization_Success(t *testing.T) {
	responseJSON := `{
		"id": "org-123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-central1",
		"displayName": "Test Organization",
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
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	// Call TfOrganization
	result, err := service.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{
		ID: "org-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "org-123", result.ID)
	require.Equal(t, "gcp-hub-project-12345", result.ProjectID)
	require.Equal(t, "123456789012", result.OrganizationID)
	require.Equal(t, "terraform_provider", result.OnboardingType)
	require.Equal(t, "us-central1", result.Region)
	require.Equal(t, "Test Organization", result.DisplayName)
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

func TestTfOrganization_WithServicesData(t *testing.T) {
	responseJSON := `{
		"id": "org-123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "standard",
		"status": "Partially added",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Partially added",
				"errors": ["some error"]
			}
		]
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	result, err := service.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{
		ID: "org-123",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.ServicesData, 1)
	require.Equal(t, "sca", result.ServicesData[0].Name)
	require.Equal(t, "Partially added", result.ServicesData[0].Status)
	require.Equal(t, []string{"some error"}, result.ServicesData[0].Errors)
}

func TestOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{ID: "org-123"})
		return err
	})
}
