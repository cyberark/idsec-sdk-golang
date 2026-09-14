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

func TestTfAddOrganization_Success(t *testing.T) {
	createResponseJSON := `{"id": "org-onboarding-abc123"}`

	getResponseJSON := `{
		"id": "org-onboarding-abc123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-central1",
		"displayName": "",
		"status": "Completely added",
		"services": ["dpa"],
		"servicesData": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		]
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-onboarding-abc123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	input := &gcpmodels.TfIdsecCCEGCPAddOrganization{
		DeploymentProjectID: "gcp-hub-project-12345",
		OrganizationID:      "123456789012",
		ProjectNumber:       "987654321098",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources:   map[string]interface{}{"someKey": "someValue"},
			},
		},
		CCEResources: gcpmodels.TfIdsecCCEGCPResources{
			WorkloadIdentityPoolID:     "pool-abc",
			WorkloadIdentityProviderID: "provider-abc",
			TargetServiceAccountEmail:  "sa@gcp-hub-project-12345.iam.gserviceaccount.com",
		},
	}

	result, err := service.TfAddOrganization(input)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "org-onboarding-abc123", result.ID)
	require.Equal(t, "gcp-hub-project-12345", result.ProjectID)
	require.Equal(t, "123456789012", result.OrganizationID)
	require.Equal(t, "terraform_provider", result.OnboardingType)
	require.Equal(t, []string{"dpa"}, result.Services)
}

func TestTfAddOrganization_IncludesDeploymentAndOnboardingType(t *testing.T) {
	createResponseJSON := `{"id": "org-onboarding-abc123"}`
	getResponseJSON := `{
		"id": "org-onboarding-abc123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "terraform_provider",
		"status": "Completely added",
		"services": ["dpa"]
	}`

	var capturedBody map[string]interface{}
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual"
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
			OnRequest: func(r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				json.Unmarshal(body, &capturedBody)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-onboarding-abc123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	_, err := service.TfAddOrganization(&gcpmodels.TfIdsecCCEGCPAddOrganization{
		DeploymentProjectID: "gcp-hub-project-12345",
		OrganizationID:      "123456789012",
		ProjectNumber:       "987654321098",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
		},
		CCEResources: gcpmodels.TfIdsecCCEGCPResources{},
	})

	require.NoError(t, err)
	require.Equal(t, "organization", capturedBody["deploymentType"],
		"POST body must include deploymentType=organization")
	require.Equal(t, ccemodels.TerraformProvider, capturedBody["onboardingType"],
		"POST body must include onboardingType=terraform_provider")
}

func TestTfAddOrganization_IncludesServiceVersion(t *testing.T) {
	createResponseJSON := `{"id": "org-onboarding-abc123"}`
	getResponseJSON := `{
		"id": "org-onboarding-abc123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "terraform_provider",
		"status": "Completely added",
		"services": ["dpa"]
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
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-onboarding-abc123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	_, err := service.TfAddOrganization(&gcpmodels.TfIdsecCCEGCPAddOrganization{
		DeploymentProjectID: "gcp-hub-project-12345",
		OrganizationID:      "123456789012",
		ProjectNumber:       "987654321098",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Version: "2.1.0", Resources: map[string]interface{}{}},
		},
		CCEResources: gcpmodels.TfIdsecCCEGCPResources{},
	})

	require.NoError(t, err)
	require.Equal(t, "2.1.0", capturedVersion,
		"service version must be included in the create organization request payload")
}

func TestTfUpdateOrganization_Success(t *testing.T) {
	getCurrentResponseJSON := `{
		"id": "org-123",
		"services": ["dpa"]
	}`

	addServicesResponseJSON := `{}`
	deleteServicesResponseJSON := `{}`

	getUpdatedResponseJSON := `{
		"id": "org-123",
		"projectId": "gcp-hub-project-12345",
		"organizationId": "123456789012",
		"onboardingType": "terraform_provider",
		"status": "Completely added",
		"services": ["sca", "secrets_hub"]
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-123" && getCallCount == 0 {
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
				return r.Method == "POST" && r.URL.Path == "/api/gcp/manual/org-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/gcp/manual/org-123/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/gcp/manual/organization/org-123" && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: getUpdatedResponseJSON,
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	input := &gcpmodels.TfIdsecCCEGCPUpdateOrganization{
		ID: "org-123",
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.SCA, Resources: map[string]interface{}{}},
			{ServiceName: ccemodels.SecretsHub, Resources: map[string]interface{}{}},
		},
	}

	result, err := service.TfUpdateOrganization(input)

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "org-123", result.ID)
}

func TestTfDeleteOrganization_Success(t *testing.T) {
	var gotQuery map[string][]string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && r.URL.Path == "/api/gcp/manual/org-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				gotQuery = r.URL.Query()
			},
		},
	})
	defer cleanup()

	service := setupGCPService(client)

	err := service.TfDeleteOrganization(&gcpmodels.TfIdsecCCEGCPDeleteOrganization{
		ID: "org-123",
	})

	require.NoError(t, err)
	require.Equal(t, []string{ccemodels.TerraformProvider}, gotQuery["onboarding_type"],
		"DELETE must send onboarding_type=terraform_provider query param")
}

func TestTfAddOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfAddOrganization(&gcpmodels.TfIdsecCCEGCPAddOrganization{
			DeploymentProjectID: "proj",
			OrganizationID:      "123",
			ProjectNumber:       "456",
			Services:            []ccemodels.IdsecCCEServiceInput{{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}}},
			CCEResources:        gcpmodels.TfIdsecCCEGCPResources{},
		})
		return err
	})
}

func TestTfDeleteOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		return service.TfDeleteOrganization(&gcpmodels.TfIdsecCCEGCPDeleteOrganization{ID: "org-123"})
	})
}

func TestTfUpdateOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupGCPService(client)
		_, err := service.TfUpdateOrganization(&gcpmodels.TfIdsecCCEGCPUpdateOrganization{
			ID: "org-123",
			Services: []ccemodels.IdsecCCEServiceInput{
				{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
			},
		})
		return err
	})
}
