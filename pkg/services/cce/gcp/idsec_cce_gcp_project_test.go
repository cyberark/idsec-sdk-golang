package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
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

// TestTfAddProject_Success verifies that adding a GCP Project posts to /api/gcp/manual
// and returns the freshly created project details fetched from the programmatic get endpoint.
func TestTfAddProject_Success(t *testing.T) {
	createResponseJSON := `{"id": "project-123"}`
	getResponseJSON := `{
		"id": "project-123",
		"projectId": "gcp-project-12345",
		"onboardingType": "terraform_provider",
		"status": "Completely added"
	}`

	var gotBody map[string]interface{}
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
			OnRequest: func(r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &gotBody)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	result, err := service.TfAddProject(&gcpmodels.TfIdsecCCEGCPAddProject{
		ProjectID:      "gcp-project-12345",
		OrganizationID: "123456789012",
		ProjectNumber:  "987654321012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources:   map[string]interface{}{"appId": "app-123"},
			},
		},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "project-123", result.ID)
	require.Equal(t, "gcp-project-12345", result.ProjectID)

	// Request body assertions: deploymentProjectId/organizationId/projectNumber must be sent
	// on the wire, alongside the generic deploymentType/onboardingType injected by ManualClient.
	require.Equal(t, "gcp-project-12345", gotBody["deploymentProjectId"])
	require.Equal(t, "123456789012", gotBody["organizationId"])
	require.Equal(t, "987654321012", gotBody["projectNumber"])
	require.Equal(t, "standalone", gotBody["deploymentType"])
	require.Equal(t, string(ccemodels.TerraformProvider), gotBody["onboardingType"])
}

// TestTfUpdateProject_Success verifies that updating a GCP Project's services reconciles
// against the current services and returns the refreshed project details.
func TestTfUpdateProject_Success(t *testing.T) {
	getCurrentResponseJSON := `{
		"id": "project-123",
		"services": ["epm"]
	}`
	addServicesResponseJSON := `{}`
	deleteServicesResponseJSON := `{}`
	getUpdatedResponseJSON := `{
		"id": "project-123",
		"projectId": "gcp-project-12345",
		"onboardingType": "terraform_provider",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123" && getCallCount == 0 {
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
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual/project-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/gcp/manual/project-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	result, err := service.TfUpdateProject(&gcpmodels.TfIdsecCCEGCPUpdateProject{
		ID: "project-123",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
			{ServiceName: ccemodels.SCA, Resources: map[string]interface{}{}},
		},
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "project-123", result.ID)
}

// TestTfDeleteProject_Success verifies that deleting a GCP Project issues a DELETE to
// /api/gcp/manual/{id}.
func TestTfDeleteProject_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/gcp/manual/project-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	err := service.TfDeleteProject(&gcpmodels.TfIdsecCCEGCPDeleteProject{ID: "project-123"})

	require.NoError(t, err)
}

func TestAddProject_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfAddProject(&gcpmodels.TfIdsecCCEGCPAddProject{
			ProjectID:      "gcp-project-12345",
			OrganizationID: "123456789012",
			ProjectNumber:  "987654321012",
			Services: []ccemodels.IdsecCCEServiceInput{
				{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
			},
		})
		return err
	})
}

func TestUpdateProject_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfUpdateProject(&gcpmodels.TfIdsecCCEGCPUpdateProject{
			ID: "project-123",
			Services: []ccemodels.IdsecCCEServiceInput{
				{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
			},
		})
		return err
	})
}

func TestDeleteProject_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		return service.TfDeleteProject(&gcpmodels.TfIdsecCCEGCPDeleteProject{ID: "project-123"})
	})
}

func TestTfAddProject_IncludesServiceVersion(t *testing.T) {
	createResponseJSON := `{"id": "project-123"}`
	getResponseJSON := `{
		"id": "project-123",
		"projectId": "gcp-project-12345",
		"onboardingType": "terraform_provider",
		"status": "Completely added"
	}`

	var capturedVersion string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
			OnRequest: func(r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var payload map[string]interface{}
				json.Unmarshal(body, &payload)
				if services, ok := payload["services"].([]interface{}); ok && len(services) > 0 {
					if svc, ok := services[0].(map[string]interface{}); ok {
						capturedVersion, _ = svc["version"].(string)
					}
				}
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/project/project-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	_, err := service.TfAddProject(&gcpmodels.TfIdsecCCEGCPAddProject{
		ProjectID:      "gcp-project-12345",
		OrganizationID: "123456789012",
		ProjectNumber:  "987654321012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Version: "2.1.0", Resources: map[string]interface{}{}},
		},
	})

	require.NoError(t, err)
	require.Equal(t, "2.1.0", capturedVersion,
		"service version must be included in the create project request payload")
}
