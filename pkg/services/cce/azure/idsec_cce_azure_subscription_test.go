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

func TestTfAddSubscription_Success(t *testing.T) {
	// Mock response for POST /api/azure/manual (create)
	createResponseJSON := `{
		"id": "subscription-123"
	}`

	// Mock response for GET /api/azure/manual/subscription/{id} (retrieve)
	subscriptionID := "sub-12345678-1234-1234-1234-123456789012"
	subscriptionName := "Test Subscription"
	entraTenantName := "TestTenant"
	getResponseJSON := `{
		"id": "subscription-123",
		"onboardingType": "terraform_provider",
		"region": "westus",
		"displayName": "Test Subscription",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"subscriptionId": "sub-12345678-1234-1234-1234-123456789012"
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
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/subscription/subscription-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create input
	input := &azuremodels.TfIdsecCCEAzureAddSubscription{
		EntraID:          "12345678-1234-1234-1234-123456789012",
		EntraTenantName:  entraTenantName,
		SubscriptionID:   subscriptionID,
		SubscriptionName: subscriptionName,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"appId": "app-123",
				},
			},
		},
	}

	// Call TfAddSubscription
	result, err := service.TfAddSubscription(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "subscription-123", result.ID)
	require.Equal(t, "sub-12345678-1234-1234-1234-123456789012", result.SubscriptionID)
}

func TestTfSubscription_Success(t *testing.T) {
	responseJSON := `{
		"id": "subscription-123",
		"onboardingType": "terraform_provider",
		"region": "westus",
		"displayName": "Test Subscription",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"subscriptionId": "sub-12345678-1234-1234-1234-123456789012"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/subscription/subscription-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfSubscription
	result, err := service.TfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{
		ID: "subscription-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "subscription-123", result.ID)
	require.Equal(t, "sub-12345678-1234-1234-1234-123456789012", result.SubscriptionID)
}

func TestTfUpdateSubscription_Success(t *testing.T) {
	// Mock response for initial GET /api/azure/manual/subscription/{id} (get current state)
	getCurrentResponseJSON := `{
		"id": "subscription-123",
		"services": ["EPM"]
	}`

	// Mock response for POST /api/azure/manual/{id}/services (add services)
	addServicesResponseJSON := `{}`

	// Mock response for DELETE /api/azure/manual/{id}/services (remove services)
	deleteServicesResponseJSON := `{}`

	// Mock response for final GET /api/azure/manual/subscription/{id} (get updated state)
	getUpdatedResponseJSON := `{
		"id": "subscription-123",
		"onboardingType": "terraform_provider",
		"region": "westus",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"subscriptionId": "sub-12345678-1234-1234-1234-123456789012"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && r.URL.Path == "/api/azure/manual/subscription/subscription-123" && getCallCount == 0 {
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
				return r.Method == "POST" && r.URL.Path == "/api/azure/manual/subscription-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/subscription-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/subscription/subscription-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Create update input with new services
	input := &azuremodels.TfIdsecCCEAzureUpdateSubscription{
		ID: "subscription-123",
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

	// Call TfUpdateSubscription
	result, err := service.TfUpdateSubscription(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "subscription-123", result.ID)
}

func TestTfDeleteSubscription_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/subscription-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfDeleteSubscription
	err := service.TfDeleteSubscription(&azuremodels.TfIdsecCCEAzureDeleteSubscription{
		ID: "subscription-123",
	})

	// Assertions
	require.NoError(t, err)
}

func TestSubscription_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAzureService(client)
		_, err := service.TfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: "subscription-123"})
		return err
	})
}
