package aws

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// setupAWSService creates an IdsecCCEAWSService with the given mock ISP client.
func setupAWSService(client *isp.IdsecISPServiceClient) *IdsecCCEAWSService {
	return &IdsecCCEAWSService{
		client: client,
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
	}
}

func TestTfAddAccount_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: POST /api/aws/programmatic/account (create)
	createResponseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc"
	}`

	// Second response: GET /api/aws/programmatic/account/{id} (read)
	readResponseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Setup mock service with multiple responses
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: readResponseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the TfAddAccount function
	result, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
		AccountID: "123456789012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions - now expects full account details
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, "123456789012", result.AccountID)
	require.Equal(t, ccemodels.TerraformProvider, result.OnboardingType)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestTfAddAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
			AccountID: "123456789012",
			Services:  []ccemodels.IdsecCCEServiceInput{},
		})
		return err
	})
}

func TestTfAddAccount_EmptyServicesArray_Returns400(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"attributes": null,
				"code": "400",
				"description": "One or more programmatic values is invalid.",
				"message": "Bad Request"
			}`,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Contains(t, r.URL.Path, "/api/aws/programmatic/account")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Attempt to create account with empty services array
	_, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
		AccountID:          "123456789012",
		Services:           []ccemodels.IdsecCCEServiceInput{}, // Empty services array
		AccountDisplayName: "Test Account",
		DeploymentRegion:   "us-east-1",
	})

	// Assertions - should return error for 400 Bad Request
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
	require.Contains(t, err.Error(), "Bad Request")
}

func TestAccount_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	responseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"parameters": {
			"dummy_two": {
				"CobTableArn": "arn:aws:dynamodb::123456789012:table/table_name"
			},
			"dummy": {}
		},
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the Account function
	result, err := service.TfAccount(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: "1111aaaa2222bbbb3333cccc",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)

	// Build expected struct
	expected := &awsmodels.TfIdsecCCEAWSAccount{
		ID:             "1111aaaa2222bbbb3333cccc",
		AccountID:      "123456789012",
		OnboardingType: ccemodels.TerraformProvider,
		Region:         region,
		// Parameters will be populated by mapstructure from JSON, keys are converted to snake_case
		Parameters: map[string]map[string]interface{}{
			"dummy_two": {
				"cob_table_arn": "arn:aws:dynamodb::123456789012:table/table_name",
			},
			"dummy": {},
		},
		DisplayName: displayName,
		Status:      status,
	}

	// Compare structs
	require.Equal(t, expected, result)
}

func TestAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfAccount(&awsmodels.TfIdsecCCEAWSGetAccount{
			ID: "acc-789",
		})
		return err
	})
}

func TestDeleteAccount_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the TfDeleteAccount function
	err := service.TfDeleteAccount(&awsmodels.TfIdsecCCEAWSDeleteAccount{
		ID: "1111aaaa2222bbbb3333cccc",
	})

	// Assertions
	require.NoError(t, err)
}

func TestDeleteAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		return service.TfDeleteAccount(&awsmodels.TfIdsecCCEAWSDeleteAccount{
			ID: "acc-789",
		})
	})
}

func TestUpdateAccount_AddService_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with only DPA
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: POST add CDS service
	addServicesResponse := `{}`

	// Third response: GET updated account with SCA and CDS
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request to account endpoint
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON, // First GET returns current state
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to services endpoint
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON, // Second GET returns updated state
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to add CEM service
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
			{
				ServiceName: ccemodels.CDS,
				Resources: map[string]any{
					"CdsRoleArn": "arn:aws:iam::123456789012:role/CDSRole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, "123456789012", result.AccountID)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_RemoveService_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with SCA and CDS
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: DELETE CDS service
	deleteServicesResponse := `{}`

	// Third response: GET updated account with only DPA
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to add services endpoint (ServiceNames is nil, so UpdateAccount will try to add)
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE to services endpoint
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to remove CEM service
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_AddAndRemoveServices_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with SCA and CDS
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: POST add SCA service
	addServicesResponse := `{}`

	// Third response: DELETE CDS service
	deleteServicesResponse := `{}`

	// Fourth response: GET updated account with CDS and SCA
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["cds", "sca"],
		"servicesData": [
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to services endpoint
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE to services endpoint
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to add SCA and remove CEM
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.CDS,
				Resources: map[string]any{
					"CdsRoleArn": "arn:aws:iam::123456789012:role/CDSRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)

	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_NoChanges_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Since ServiceNames is nil, UpdateAccount will try to add services
	// Second response: POST to add services endpoint
	addServicesResponse := `{}`
	// Third response: GET account again (no add/remove operations)
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to add services endpoint (ServiceNames is nil, so UpdateAccount will try to add)
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount with same services (no changes)
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	// ServiceNames is populated by Deserialize method in TfAccount

	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_ErrorPropagation(t *testing.T) {
	// Test error when getting current account fails
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return true // Match any request
			},
			StatusCode:   http.StatusNotFound,
			ResponseBody: `{"error": "account not found"}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "nonexistent",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources:   map[string]any{},
			},
		},
	})
	require.Error(t, err)
}

func TestUpdateAccount_EmptyServicesArray_Returns400(t *testing.T) {
	// First response: GET current account with 1 service (DPA)
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "programmatic",
		"region": "us-east-1",
		"services": ["dpa"],
		"servicesData": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// ServiceNames is populated by Deserialize, so UpdateAccount will detect current services
	// and try to remove them, which should return a 400 error
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match GET request to fetch current account
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE request to remove services (will fail with 400)
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"code": "400",
				"message": "Bad Request",
				"description": "An account must have at least one service. If you want to remove the service, you must remove the account instead. Use the remove account API.",
				"attributes": null
			}`,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "DELETE", r.Method)
				require.Contains(t, r.URL.Path, "services")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Attempt to update account with empty services array
	// and try to delete them, which should return a 400 error
	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID:       "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{}, // Empty services array
	})

	// Assertions - should return error for 400 Bad Request
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
	require.Contains(t, err.Error(), "Bad Request")
}
