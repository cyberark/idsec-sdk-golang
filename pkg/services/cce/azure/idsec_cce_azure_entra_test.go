package azure

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// setupAzureService creates an IdsecCCEAzureService with the given mock ISP client.
func setupAzureService(client *isp.IdsecISPServiceClient) *IdsecCCEAzureService {
	return &IdsecCCEAzureService{
		client: client,
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
	}
}

func TestTfAddEntra_Success(t *testing.T) {
	// Mock response for POST /api/azure/manual (create)
	createResponseJSON := `{
		"id": "entra-123"
	}`

	// Mock response for GET /api/azure/manual/entra/{id} (retrieve)
	entraTenantName := "TestTenant"
	getResponseJSON := `{
		"id": "entra-123",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"displayName": "Test Entra Tenant",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012"
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
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/entra/entra-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create input
	input := &azuremodels.TfIdsecCCEAzureAddEntra{
		EntraID:         "12345678-1234-1234-1234-123456789012",
		EntraTenantName: entraTenantName,
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

	// Call TfAddEntra
	result, err := service.TfAddEntra(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "entra-123", result.ID)
	require.Equal(t, "12345678-1234-1234-1234-123456789012", result.EntraID)
}

func TestTfEntra_Success(t *testing.T) {
	responseJSON := `{
		"id": "entra-123",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"displayName": "Test Entra Tenant",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/entra/entra-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfEntra
	result, err := service.TfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{
		ID: "entra-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "entra-123", result.ID)
	require.Equal(t, "12345678-1234-1234-1234-123456789012", result.EntraID)
}

func TestTfUpdateEntra_Success(t *testing.T) {
	// Mock response for initial GET /api/azure/manual/entra/{id} (get current state)
	getCurrentResponseJSON := `{
		"id": "entra-123",
		"services": ["EPM"]
	}`

	// Mock response for POST /api/azure/manual/{id}/services (add services)
	addServicesResponseJSON := `{}`

	// Mock response for DELETE /api/azure/manual/{id}/services (remove services)
	deleteServicesResponseJSON := `{}`

	// Mock response for final GET /api/azure/manual/entra/{id} (get updated state)
	getUpdatedResponseJSON := `{
		"id": "entra-123",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && r.URL.Path == "/api/azure/manual/entra/entra-123" && getCallCount == 0 {
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
				return r.Method == "POST" && r.URL.Path == "/api/azure/manual/entra-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/entra-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/entra/entra-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create update input with new services
	input := &azuremodels.TfIdsecCCEAzureUpdateEntra{
		ID: "entra-123",
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

	// Call TfUpdateEntra
	result, err := service.TfUpdateEntra(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "entra-123", result.ID)
}

func TestTfDeleteEntra_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/entra-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfDeleteEntra
	err := service.TfDeleteEntra(&azuremodels.TfIdsecCCEAzureDeleteEntra{
		ID: "entra-123",
	})

	// Assertions
	require.NoError(t, err)
}

func TestEntra_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAzureService(client)
		_, err := service.TfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{ID: "entra-123"})
		return err
	})
}
