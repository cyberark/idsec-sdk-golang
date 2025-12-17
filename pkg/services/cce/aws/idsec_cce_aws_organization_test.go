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

func TestOrganization_Success(t *testing.T) {
	// Define the expected JSON response (with nullable fields)
	region := "us-east-1"
	displayName := "Test Organization"
	status := ccemodels.CompletelyAdded

	responseJSON := `{
		"id": "org-123",
		"organization_root_id": "root-456",
		"management_account_id": "123456789012",
		"organization_id": "o-abc123def",
		"onboarding_type": "programmatic",
		"region": "us-east-1",
		"services": ["dpa", "sca"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"display_name": "Test Organization",
		"status": "Completely added"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Contains(t, r.URL.Path, "org-123")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the Organization function
	result, err := service.TfOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
		ID: "org-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)

	// Build expected struct for comparison
	expected := &awsmodels.TfIdsecCCEAWSOrganization{
		ID:                  "org-123",
		OrganizationRootID:  "root-456",
		ManagementAccountID: "123456789012",
		OrganizationID:      "o-abc123def",
		OnboardingType:      ccemodels.Programmatic,
		Region:              region,
		DisplayName:         displayName,
		Status:              status,
	}

	// Compare entire struct
	require.Equal(t, expected, result)
}

func TestOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
			ID: "org-456",
		})
		return err
	})
}

func TestOrganizationDatasource_Success(t *testing.T) {
	// Define the expected JSON response with services and servicesData fields
	region := "us-east-1"
	displayName := "Test Organization"
	status := ccemodels.CompletelyAdded

	responseJSON := `{
		"id": "org-123",
		"organization_root_id": "root-456",
		"management_account_id": "123456789012",
		"organization_id": "o-abc123def",
		"onboarding_type": "programmatic",
		"region": "us-east-1",
		"services": ["dpa", "sca"],
		"services_data": [
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
		"display_name": "Test Organization",
		"status": "Completely added"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Contains(t, r.URL.Path, "org-123")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the TfOrganizationDatasource function
	result, err := service.TfOrganizationDatasource(&awsmodels.TfIdsecCCEAWSGetOrganization{
		ID: "org-123",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify embedded struct fields
	require.Equal(t, "org-123", result.ID)
	require.Equal(t, "root-456", result.OrganizationRootID)
	require.Equal(t, "123456789012", result.ManagementAccountID)
	require.Equal(t, "o-abc123def", result.OrganizationID)
	require.Equal(t, ccemodels.Programmatic, result.OnboardingType)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)

	// Verify new fields
	require.Len(t, result.Services, 2)
	require.Contains(t, result.Services, "dpa")
	require.Contains(t, result.Services, "sca")
	require.Len(t, result.ServicesData, 2)
	require.Equal(t, "dpa", result.ServicesData[0].Name)
	require.Equal(t, "Completely added", result.ServicesData[0].Status)
	require.Equal(t, "sca", result.ServicesData[1].Name)
	require.Equal(t, "Completely added", result.ServicesData[1].Status)
}

func TestOrganizationDatasource_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfOrganizationDatasource(&awsmodels.TfIdsecCCEAWSGetOrganization{
			ID: "org-456",
		})
		return err
	})
}

func TestAddOrganization_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/aws/programmatic/organization"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"id": "abc123def456789012345678901234ab"}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/aws/programmatic/organization/abc123def456789012345678901234ab"
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "abc123def456789012345678901234ab",
				"organization_root_id": "r-abc123",
				"management_account_id": "123456789012",
				"organization_id": "o-abc123def456",
				"onboarding_type": "programmatic",
				"region": "us-east-1",
				"service_names": ["dpa"],
				"services_data": [
					{
						"name": "dpa",
						"status": "Completely added",
						"errors": []
					}
				],
				"display_name": "Test Organization",
				"status": "Completely added"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)
	displayName := "Test Organization"

	// Call the AddOrganization function
	result, err := service.TfAddOrganization(&awsmodels.TfIdsecCCEAWSAddOrganization{
		OrganizationRootID:  "r-abc123",
		ManagementAccountID: "123456789012",
		OrganizationID:      "o-abc123def456",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::123456789012:role/DpaRole",
				},
			},
		},
		OrganizationDisplayName:    displayName,
		ScanOrganizationRoleArn:    "arn:aws:iam::123456789012:role/ScanRole",
		CrossAccountRoleExternalID: "cyberark-12345678-1234-1234-1234-123456789012",
	})

	// Assertions - verify the full organization structure is returned
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "abc123def456789012345678901234ab", result.ID)
	require.Equal(t, "r-abc123", result.OrganizationRootID)
	require.Equal(t, "123456789012", result.ManagementAccountID)
	require.Equal(t, "o-abc123def456", result.OrganizationID)
	require.Equal(t, ccemodels.Programmatic, result.OnboardingType)
	require.NotNil(t, result.DisplayName)
	require.Equal(t, "Test Organization", result.DisplayName)
}

func TestAddOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		displayName := "Test Organization"
		_, err := service.TfAddOrganization(&awsmodels.TfIdsecCCEAWSAddOrganization{
			OrganizationRootID:  "r-abc123",
			ManagementAccountID: "123456789012",
			OrganizationID:      "o-abc123def456",
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::123456789012:role/DpaRole",
					},
				},
			},
			OrganizationDisplayName:    displayName,
			ScanOrganizationRoleArn:    "arn:aws:iam::123456789012:role/ScanRole",
			CrossAccountRoleExternalID: "cyberark-12345678-1234-1234-1234-123456789012",
		})
		return err
	})
}

func TestDeleteOrganization_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "DELETE", r.Method)
				require.Contains(t, r.URL.Path, "abc123def456789012345678901234ab")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the DeleteOrganization function
	err := service.TfDeleteOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
		ID: "abc123def456789012345678901234ab",
	})

	// Assertions
	require.NoError(t, err)
}

func TestDeleteOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		return service.TfDeleteOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
			ID: "abc123def456789012345678901234ab",
		})
	})
}

func TestUpdateOrganization_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Organization"
	status := ccemodels.CompletelyAdded

	// First response: GET current organization with SCA and DPA
	currentOrganizationJSON := `{
		"id": "org123abc456def789",
		"organization_root_id": "r-abc123",
		"management_account_id": "123456789012",
		"organization_id": "o-abc123def456",
		"onboarding_type": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "dpa"],
		"services_data": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"display_name": "Test Organization",
		"status": "Completely added"
	}`

	// Second response: POST add SecretsHub service
	addServicesResponse := `{}`

	// Third response: DELETE remove DPA service
	deleteServicesResponse := `{}`

	// Fourth response: GET updated organization with SCA and SecretsHub
	updatedOrganizationJSON := `{
		"id": "org123abc456def789",
		"organization_root_id": "r-abc123",
		"management_account_id": "123456789012",
		"organization_id": "o-abc123def456",
		"onboarding_type": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "secrets_hub"],
		"services_data": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "secrets_hub",
				"status": "Completely added",
				"errors": []
			}
		],
		"display_name": "Test Organization",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request to organization endpoint
				if r.Method == "GET" && strings.Contains(r.URL.Path, "org123abc456def789") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentOrganizationJSON, // First GET returns current state
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to services endpoint (adding SecretsHub)
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE to services endpoint (removing DPA)
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "org123abc456def789") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedOrganizationJSON, // Second GET returns updated state
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateOrganization - keeping SCA, removing DPA, adding SecretsHub
	result, err := service.TfUpdateOrganization(&awsmodels.TfIdsecCCEAWSUpdateOrganization{
		ID: "org123abc456def789",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/ScaRole",
				},
			},
			{
				ServiceName: ccemodels.SecretsHub,
				Resources: map[string]any{
					"SecretsHubRoleArn": "arn:aws:iam::123456789012:role/SecretsHubRole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "org123abc456def789", result.ID)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfUpdateOrganization(&awsmodels.TfIdsecCCEAWSUpdateOrganization{
			ID: "nonexistent",
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.SCA,
					Resources: map[string]any{
						"ScaRoleArn": "arn:aws:iam::123456789012:role/ScaRole",
					},
				},
			},
		})
		return err
	})
}
