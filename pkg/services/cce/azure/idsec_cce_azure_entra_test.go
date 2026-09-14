package azure

import (
	"io"
	"net/http"
	"reflect"
	"testing"
	"unsafe"

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
	ispBase := &services.IdsecISPBaseService{}
	// Use reflection to set the private client field for testing
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecCCEAzureService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}

func TestTfAddEntra_Success(t *testing.T) {
	// Mock response for POST /api/azure/manual (create)
	createResponseJSON := `{
		"id": "entra-123"
	}`

	// Mock response for GET /api/azure/manual/entra/{id} (retrieve)
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
		EntraID: "12345678-1234-1234-1234-123456789012",
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

func TestTfAddEntra_IncludesServiceVersion(t *testing.T) {
	createResponseJSON := `{"id": "entra-123"}`
	getResponseJSON := `{
		"id": "entra-123",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"displayName": "Test Entra Tenant",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012"
	}`

	var capturedVersion string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/azure/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
			OnRequest:    captureFirstServiceVersion(&capturedVersion),
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

	_, err := service.TfAddEntra(&azuremodels.TfIdsecCCEAzureAddEntra{
		EntraID: "12345678-1234-1234-1234-123456789012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Version:     "1.5.0",
				Resources:   map[string]interface{}{"appId": "app-123"},
			},
		},
		CCEResources: map[string]interface{}{},
	})

	require.NoError(t, err)
	require.Equal(t, "1.5.0", capturedVersion, "service version must be included in the create entra request payload")
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

// TestTfUpdateEntra_UpsertsChangedServiceInput is a regression guard for two related bugs
// (mirroring the AWS fix in idsec_cce_aws_account_test.go), now applied to Azure's Entra
// (organization-level) update path:
//  1. the original "silent no-op on version change": a name-only diff sends only brand-new
//     service names, so bumping the version of an already-onboarded service produced a green
//     apply with no API call and no server change; and
//  2. the follow-up "501 on unchanged service": naively re-sending the full desired list makes
//     the API reject already-onboarded services that are not an upgrade (e.g. dpa) with a 501,
//     because the add/update-services endpoint only supports adding new services or upgrading a
//     version/resources - not re-submitting an unchanged service.
//
// So the update must send only new and version-changed services: here dpa is unchanged
// (0.0.3 -> 0.0.3) and must be omitted, while sca is upgraded (0.0.3 -> 0.0.4) and must be sent.
func TestTfUpdateEntra_UpsertsChangedServiceInput(t *testing.T) {
	// dpa and sca are already onboarded at 0.0.3; the GET exposes their versions under "servicesData".
	getCurrentResponseJSON := `{
		"id": "entra-123",
		"services": ["dpa", "sca"],
		"servicesData": [
			{"name": "dpa", "version": "0.0.3", "status": "Completely added", "errors": []},
			{"name": "sca", "version": "0.0.3", "status": "Completely added", "errors": []}
		]
	}`
	getUpdatedResponseJSON := `{
		"id": "entra-123",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012"
	}`

	var postBody string
	var postCount, deleteCount int
	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
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
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				postCount++
				body, _ := io.ReadAll(r.Body)
				postBody = string(body)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/entra-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest:    func(r *http.Request) { deleteCount++ },
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/manual/entra/entra-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	_, err := service.TfUpdateEntra(&azuremodels.TfIdsecCCEAzureUpdateEntra{
		ID: "entra-123",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]interface{}{}},
			{ServiceName: ccemodels.SCA, Version: "0.0.4", Resources: map[string]interface{}{}},
		},
	})

	require.NoError(t, err)
	require.Equal(t, 1, postCount, "a version change on one service must trigger exactly one add/update-services call")
	require.Contains(t, postBody, `"serviceName":"sca"`, "the upgraded service (sca) must be sent")
	require.Contains(t, postBody, `"version":"0.0.4"`, "the new sca version must be sent")
	require.NotContains(t, postBody, `"serviceName":"dpa"`,
		"the unchanged service (dpa) must NOT be sent, or the API rejects the request with 501")
	require.Zero(t, deleteCount, "a version change on an existing service must not delete any service")
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
