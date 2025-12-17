package azure

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfAddManagementGroup_Success(t *testing.T) {
	// Mock response for POST /api/azure/manual (create)
	createResponseJSON := `{
		"id": "mgmt-group-123"
	}`

	// Mock response for GET /api/azure/manual/mgmtgroup/{id} (retrieve)
	mgmtGroupID := "mg-test-group"
	getResponseJSON := `{
		"id": "mgmt-group-123",
		"onboardingType": "terraform_provider",
		"region": "eastus",
		"displayName": "Test Management Group",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"managementGroupId": "mg-test-group"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/azure/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/mgmtgroup/mgmt-group-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create input
	input := &azuremodels.TfIdsecCCEAzureAddManagementGroup{
		EntraID:           "12345678-1234-1234-1234-123456789012",
		ManagementGroupID: mgmtGroupID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"appId": "app-123",
				},
			},
		},
		CCEResources: map[string]interface{}{},
	}

	// Call TfAddManagementGroup
	result, err := service.TfAddManagementGroup(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "mgmt-group-123", result.ID)
	require.Equal(t, "mg-test-group", result.ManagementGroupID)
}

func TestTfManagementGroup_Success(t *testing.T) {
	responseJSON := `{
		"id": "mgmt-group-123",
		"onboardingType": "terraform_provider",
		"region": "eastus",
		"displayName": "Test Management Group",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"managementGroupId": "mg-test-group"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/mgmtgroup/mgmt-group-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfManagementGroup
	result, err := service.TfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{
		ID: "mgmt-group-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "mgmt-group-123", result.ID)
	require.Equal(t, "mg-test-group", result.ManagementGroupID)
}

func TestTfUpdateManagementGroup_Success(t *testing.T) {
	// Mock response for initial GET /api/azure/manual/mgmtgroup/{id} (get current state)
	getCurrentResponseJSON := `{
		"id": "mgmt-group-123",
		"services": ["EPM"]
	}`

	// Mock response for POST /api/azure/manual/{id}/services (add services)
	addServicesResponseJSON := `{}`

	// Mock response for DELETE /api/azure/manual/{id}/services (remove services)
	deleteServicesResponseJSON := `{}`

	// Mock response for final GET /api/azure/manual/mgmtgroup/{id} (get updated state)
	getUpdatedResponseJSON := `{
		"id": "mgmt-group-123",
		"onboardingType": "terraform_provider",
		"region": "eastus",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"managementGroupId": "mg-test-group"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && r.URL.Path == "/api/azure/manual/mgmtgroup/mgmt-group-123" && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getCurrentResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/azure/manual/mgmt-group-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/mgmt-group-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/mgmtgroup/mgmt-group-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create update input with new services
	input := &azuremodels.TfIdsecCCEAzureUpdateManagementGroup{
		ID: "mgmt-group-123",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources:   map[string]interface{}{},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources:   map[string]interface{}{},
			},
		},
	}

	// Call TfUpdateManagementGroup
	result, err := service.TfUpdateManagementGroup(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "mgmt-group-123", result.ID)
}

func TestTfDeleteManagementGroup_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/mgmt-group-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfDeleteManagementGroup
	err := service.TfDeleteManagementGroup(&azuremodels.TfIdsecCCEAzureDeleteManagementGroup{
		ID: "mgmt-group-123",
	})

	// Assertions
	require.NoError(t, err)
}

func TestManagementGroup_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAzureService(client)
		_, err := service.TfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: "mgmt-group-123"})
		return err
	})
}
