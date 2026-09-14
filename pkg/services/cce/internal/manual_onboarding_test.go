package internal

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// testManualBasePath is a platform-agnostic base path used across these tests, standing
// in for a real "/api/{platform}/manual" path (e.g. "/api/azure/manual", "/api/gcp/manual").
const testManualBasePath = "/api/test/manual"

func newTestManualClient(client *isp.IdsecISPServiceClient) *ManualClient {
	return NewManualClient(client, common.GlobalLogger, testManualBasePath)
}

// TestManualClient_Create_InjectsDeploymentTypeAndOnboardingType verifies that Create
// injects deploymentType and onboardingType=terraform_provider into the request body,
// and returns the ID from the response.
func TestManualClient_Create_InjectsDeploymentTypeAndOnboardingType(t *testing.T) {
	var gotBody map[string]interface{}

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodPost && r.URL.Path == testManualBasePath
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"id": "onboarding-123"}`,
			OnRequest: func(r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &gotBody)
			},
		},
	})
	defer cleanup()

	manual := newTestManualClient(client)
	id, err := manual.Create(map[string]interface{}{"someField": "value"}, DeploymentTypeStandalone)

	require.NoError(t, err)
	require.Equal(t, "onboarding-123", id)
	require.Equal(t, DeploymentTypeStandalone, gotBody[RequestKeyDeploymentType])
	require.Equal(t, string(ccemodels.TerraformProvider), gotBody[RequestKeyOnboardingType])
	require.Equal(t, "value", gotBody["someField"])
}

// TestManualClient_Delete_SendsOnboardingType verifies that Delete sends
// onboarding_type=terraform_provider as a query parameter.
func TestManualClient_Delete_SendsOnboardingType(t *testing.T) {
	var gotQuery map[string][]string

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete && r.URL.Path == testManualBasePath+"/onboarding-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				gotQuery = r.URL.Query()
			},
		},
	})
	defer cleanup()

	manual := newTestManualClient(client)
	err := manual.Delete("onboarding-123")

	require.NoError(t, err)
	require.Equal(t, []string{string(ccemodels.TerraformProvider)}, gotQuery[RequestKeyOnboardingTypeQueryParam])
}

// TestManualClient_UpdateServices_DeleteSendsOnboardingType verifies that the
// delete-services request carries both the removed service names and
// onboarding_type=terraform_provider so the API enforces that the entity was onboarded via Terraform.
func TestManualClient_UpdateServices_DeleteSendsOnboardingType(t *testing.T) {
	const onboardingID = "entra123abc456"

	var gotQuery map[string][]string
	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete &&
					r.URL.Path == testManualBasePath+"/"+onboardingID+"/services"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				gotQuery = r.URL.Query()
			},
		},
	})
	defer cleanup()

	manual := newTestManualClient(client)

	// current has dpa+sca, desired keeps only sca -> the flow issues a single
	// DELETE removing "dpa" (no add calls), which is the request under test.
	err := manual.UpdateServices(
		onboardingID,
		[]string{"dpa", "sca"},
		[]ccemodels.IdsecCCEServiceInput{{ServiceName: "sca"}},
		"entra",
	)

	require.NoError(t, err)
	require.Equal(t, []string{"dpa"}, gotQuery["services_names"],
		"delete-services must send the services to remove via services_names")
	require.Equal(t, []string{string(ccemodels.TerraformProvider)}, gotQuery[RequestKeyOnboardingTypeQueryParam],
		"delete-services must send onboarding_type=terraform_provider so the API enforces the Terraform onboarding type")
}

// Helper functions to reduce code duplication

// captureAddedServices returns a callback that captures services from POST request body
func captureAddedServices(capturedServices *[]ccemodels.IdsecCCEServiceInput) func(*http.Request) {
	return func(r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var requestData map[string]interface{}
		_ = json.Unmarshal(body, &requestData)
		if services, ok := requestData["services"].([]interface{}); ok {
			for _, svc := range services {
				svcBytes, _ := json.Marshal(svc)
				var service ccemodels.IdsecCCEServiceInput
				_ = json.Unmarshal(svcBytes, &service)
				*capturedServices = append(*capturedServices, service)
			}
		}
	}
}

// captureDeletedServices returns a callback that captures services from DELETE query params
func captureDeletedServices(deletedServices *[]string) func(*http.Request) {
	return func(r *http.Request) {
		*deletedServices = r.URL.Query()["services_names"]
	}
}

// createPostMock creates a standard POST mock configuration
func createPostMock(onRequest func(*http.Request)) MockEndpointConfig {
	return MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "POST" && r.URL.Path == testManualBasePath+"/test-id/services"
		},
		StatusCode:   http.StatusOK,
		ResponseBody: `{}`,
		OnRequest:    onRequest,
	}
}

// createDeleteMock creates a standard DELETE mock configuration
func createDeleteMock(onRequest func(*http.Request)) MockEndpointConfig {
	return MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "DELETE" && r.URL.Path == testManualBasePath+"/test-id/services"
		},
		StatusCode:   http.StatusOK,
		ResponseBody: `{}`,
		OnRequest:    onRequest,
	}
}

// makeServices creates a slice of IdsecCCEServiceInput from service names
func makeServices(names ...string) []ccemodels.IdsecCCEServiceInput {
	services := make([]ccemodels.IdsecCCEServiceInput, len(names))
	for i, name := range names {
		services[i] = ccemodels.IdsecCCEServiceInput{
			ServiceName: name,
			Resources:   map[string]interface{}{},
		}
	}
	return services
}

// assertServiceNames asserts that the services list contains exactly the expected service names
func assertServiceNames(t *testing.T, services []ccemodels.IdsecCCEServiceInput, expected ...string) {
	t.Helper()
	require.Len(t, services, len(expected))
	names := make([]string, len(services))
	for i, svc := range services {
		names[i] = string(svc.ServiceName)
	}
	for _, exp := range expected {
		require.Contains(t, names, exp)
	}
}

// assertStringSliceContains asserts that the slice contains exactly the expected strings
func assertStringSliceContains(t *testing.T, actual []string, expected ...string) {
	t.Helper()
	require.Len(t, actual, len(expected))
	for _, exp := range expected {
		require.Contains(t, actual, exp)
	}
}

// TestManualClient_UpdateServices_ServiceChanges tests various service change scenarios.
// This is the single, platform-agnostic home for the add/remove reconcile logic that used
// to be duplicated per platform (Azure, GCP, ...).
func TestManualClient_UpdateServices_ServiceChanges(t *testing.T) {
	tests := []struct {
		name          string
		current       []string
		desired       []ccemodels.IdsecCCEServiceInput
		expectAdded   []string
		expectDeleted []string
	}{
		{
			name:          "AddOnly",
			current:       []string{},
			desired:       makeServices(string(ccemodels.DPA), string(ccemodels.SCA)),
			expectAdded:   []string{string(ccemodels.DPA), string(ccemodels.SCA)},
			expectDeleted: []string{},
		},
		{
			name:          "AddToExisting",
			current:       []string{"epm"},
			desired:       makeServices("epm", string(ccemodels.DPA), string(ccemodels.SCA)),
			expectAdded:   []string{string(ccemodels.DPA), string(ccemodels.SCA)},
			expectDeleted: []string{},
		},
		{
			name:          "RemoveOnly",
			current:       []string{"epm", string(ccemodels.DPA)},
			desired:       makeServices("epm"),
			expectAdded:   []string{},
			expectDeleted: []string{string(ccemodels.DPA)},
		},
		{
			name:          "RemoveAll",
			current:       []string{"epm", string(ccemodels.DPA), string(ccemodels.SCA)},
			desired:       makeServices(),
			expectAdded:   []string{},
			expectDeleted: []string{"epm", string(ccemodels.DPA), string(ccemodels.SCA)},
		},
		{
			name:          "AddAndRemove",
			current:       []string{"epm", string(ccemodels.DPA)},
			desired:       makeServices(string(ccemodels.DPA), string(ccemodels.SCA), string(ccemodels.SecretsHub)),
			expectAdded:   []string{string(ccemodels.SCA), string(ccemodels.SecretsHub)},
			expectDeleted: []string{"epm"},
		},
		{
			name:          "ReplaceAll",
			current:       []string{"epm", string(ccemodels.DPA)},
			desired:       makeServices(string(ccemodels.SCA), string(ccemodels.SecretsHub)),
			expectAdded:   []string{string(ccemodels.SCA), string(ccemodels.SecretsHub)},
			expectDeleted: []string{"epm", string(ccemodels.DPA)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addedServices []ccemodels.IdsecCCEServiceInput
			var deletedServices []string

			mocks := []MockEndpointConfig{}
			if len(tt.expectAdded) > 0 {
				mocks = append(mocks, createPostMock(captureAddedServices(&addedServices)))
			}
			if len(tt.expectDeleted) > 0 {
				mocks = append(mocks, createDeleteMock(captureDeletedServices(&deletedServices)))
			}

			client, cleanup := SetupMockCCEService(t, mocks)
			defer cleanup()

			manual := newTestManualClient(client)
			err := manual.UpdateServices("test-id", tt.current, tt.desired, "entra")

			require.NoError(t, err)

			if len(tt.expectAdded) > 0 {
				assertServiceNames(t, addedServices, tt.expectAdded...)
			} else {
				require.Empty(t, addedServices)
			}

			if len(tt.expectDeleted) > 0 {
				assertStringSliceContains(t, deletedServices, tt.expectDeleted...)
			} else {
				require.Empty(t, deletedServices)
			}
		})
	}
}

// TestManualClient_UpdateServices_IncludesServiceVersion verifies the version field is
// preserved when services are added during an update operation.
func TestManualClient_UpdateServices_IncludesServiceVersion(t *testing.T) {
	var addedServices []ccemodels.IdsecCCEServiceInput

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		createPostMock(captureAddedServices(&addedServices)),
	})
	defer cleanup()

	manual := newTestManualClient(client)

	desired := []ccemodels.IdsecCCEServiceInput{
		{
			ServiceName: ccemodels.DPA,
			Version:     "3.2.0",
			Resources:   map[string]interface{}{"appId": "app-123"},
		},
	}

	err := manual.UpdateServices("test-id", []string{}, desired, "subscription")

	require.NoError(t, err)
	require.Len(t, addedServices, 1)
	require.Equal(t, "3.2.0", addedServices[0].Version, "service version must be preserved when adding services during update")
}

// TestManualClient_UpdateServices_NoChanges tests scenarios where no API calls should be made.
func TestManualClient_UpdateServices_NoChanges(t *testing.T) {
	tests := []struct {
		name    string
		current []string
		desired []ccemodels.IdsecCCEServiceInput
	}{
		{
			name:    "NoChanges",
			current: []string{string(ccemodels.DPA), string(ccemodels.SCA)},
			desired: makeServices(string(ccemodels.DPA), string(ccemodels.SCA)),
		},
		{
			name:    "NoChangesDifferentOrder",
			current: []string{string(ccemodels.DPA), string(ccemodels.SCA), "epm"},
			desired: makeServices(string(ccemodels.SCA), "epm", string(ccemodels.DPA)),
		},
		{
			name:    "BothEmpty",
			current: []string{},
			desired: makeServices(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			postCalled := false
			deleteCalled := false

			client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						if r.Method == "POST" {
							postCalled = true
						}
						return false
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{}`,
				},
				{
					Matcher: func(r *http.Request) bool {
						if r.Method == "DELETE" {
							deleteCalled = true
						}
						return false
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{}`,
				},
			})
			defer cleanup()

			manual := newTestManualClient(client)
			err := manual.UpdateServices("test-id", tt.current, tt.desired, "management_group")

			require.NoError(t, err)
			require.False(t, postCalled, "POST should not be called when no services to add")
			require.False(t, deleteCalled, "DELETE should not be called when no services to remove")
		})
	}
}

// TestManualClient_GetCurrentServiceState_ExtractsNamesVersionsAndParameters verifies that
// GetCurrentServiceState correctly extracts the current service names (from "services"),
// per-service versions (from "services_data"), and per-service resources (from "parameters")
// from a single GET response.
func TestManualClient_GetCurrentServiceState_ExtractsNamesVersionsAndParameters(t *testing.T) {
	entityJSON := `{
		"id": "entity-123",
		"services": ["dpa", "sca"],
		"servicesData": [
			{"name": "dpa", "version": "0.0.3", "status": "Completely added", "errors": []},
			{"name": "sca", "version": "0.0.4", "status": "Completely added", "errors": []}
		],
		"parameters": {
			"dpa": {"appId": "app-123"},
			"sca": {"roleArn": "arn:aws:iam::123456789012:role/ScaRole"}
		}
	}`

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && r.URL.Path == testManualBasePath+"/entity/entity-123"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: entityJSON,
		},
	})
	defer cleanup()

	manual := newTestManualClient(client)
	current, err := manual.GetCurrentServiceState(testManualBasePath + "/entity/entity-123")

	require.NoError(t, err)
	require.ElementsMatch(t, []string{"dpa", "sca"}, current.Names)
	require.Equal(t, map[string]string{"dpa": "0.0.3", "sca": "0.0.4"}, current.Versions)
	require.Equal(t, map[string]interface{}{"app_id": "app-123"}, current.Parameters["dpa"])
	require.Equal(t, map[string]interface{}{"role_arn": "arn:aws:iam::123456789012:role/ScaRole"}, current.Parameters["sca"])
}

// TestManualClient_UpdateServicesWithReconcile_UpsertsChangedServiceInput is a regression guard
// for two related bugs (mirroring the AWS fix in idsec_cce_aws_account_test.go):
//  1. the original "silent no-op on version change": a name-only diff sends only brand-new
//     service names, so bumping the version of an already-onboarded service produces a green
//     apply with no API call and no server change; and
//  2. the follow-up "501 on unchanged service": naively re-sending the full desired list makes
//     the API reject already-onboarded services that are not an upgrade (e.g. dpa) with a 501,
//     because the add/update-services endpoint only supports adding new services or upgrading a
//     version/resources - not re-submitting an unchanged service.
//
// So the update must send only new and version-changed services: here dpa is unchanged
// (0.0.3 -> 0.0.3) and must be omitted, while sca is upgraded (0.0.3 -> 0.0.4) and must be sent.
func TestManualClient_UpdateServicesWithReconcile_UpsertsChangedServiceInput(t *testing.T) {
	var addedServices []ccemodels.IdsecCCEServiceInput
	var deletedServices []string

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		createPostMock(captureAddedServices(&addedServices)),
		createDeleteMock(captureDeletedServices(&deletedServices)),
	})
	defer cleanup()

	manual := newTestManualClient(client)

	current := &CurrentServiceState{
		Names:    []string{string(ccemodels.DPA), string(ccemodels.SCA)},
		Versions: map[string]string{string(ccemodels.DPA): "0.0.3", string(ccemodels.SCA): "0.0.3"},
	}
	desired := []ccemodels.IdsecCCEServiceInput{
		{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]interface{}{}},
		{ServiceName: ccemodels.SCA, Version: "0.0.4", Resources: map[string]interface{}{}},
	}

	err := manual.UpdateServicesWithReconcile("test-id", current, desired, "entra")

	require.NoError(t, err)
	assertServiceNames(t, addedServices, string(ccemodels.SCA))
	require.Equal(t, "0.0.4", addedServices[0].Version, "the new sca version must be sent")
	require.Empty(t, deletedServices, "a version change on an existing service must not delete any service")
}

// TestManualClient_UpdateServicesWithReconcile_SendsResourceChange verifies that a resources-only
// change (same version) on an already-onboarded service is detected and sent, while a service
// whose resources did not change is omitted (so the endpoint does not reject it with a 501 for a
// non-upgrade-enabled service).
func TestManualClient_UpdateServicesWithReconcile_SendsResourceChange(t *testing.T) {
	var addedServices []ccemodels.IdsecCCEServiceInput
	var deletedServices []string

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		createPostMock(captureAddedServices(&addedServices)),
		createDeleteMock(captureDeletedServices(&deletedServices)),
	})
	defer cleanup()

	manual := newTestManualClient(client)

	current := &CurrentServiceState{
		Names:    []string{string(ccemodels.DPA), string(ccemodels.SCA)},
		Versions: map[string]string{string(ccemodels.DPA): "0.0.3", string(ccemodels.SCA): "0.0.3"},
		Parameters: map[string]map[string]interface{}{
			string(ccemodels.DPA): {"app_id": "app-123"},
			string(ccemodels.SCA): {"role_arn": "arn:aws:iam::123456789012:role/ScaRoleOld"},
		},
	}
	desired := []ccemodels.IdsecCCEServiceInput{
		// dpa: unchanged resources -> must be omitted.
		{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]interface{}{"appId": "app-123"}},
		// sca: resources changed (same version) -> must be sent.
		{ServiceName: ccemodels.SCA, Version: "0.0.3", Resources: map[string]interface{}{"roleArn": "arn:aws:iam::123456789012:role/ScaRoleNew"}},
	}

	err := manual.UpdateServicesWithReconcile("test-id", current, desired, "subscription")

	require.NoError(t, err)
	assertServiceNames(t, addedServices, string(ccemodels.SCA))
	require.Equal(t, "arn:aws:iam::123456789012:role/ScaRoleNew", addedServices[0].Resources["roleArn"],
		"the new sca resource value must be sent")
	require.Empty(t, deletedServices, "a resources change on an existing service must not delete any service")
}

// TestManualClient_UpdateServicesWithReconcile_OnboardedServiceWithoutVersionIsNotResent guards a
// subtle 501 regression: whether a service is "already onboarded" must be decided by the
// authoritative current.Names list, NOT by the presence of a version in current.Versions. The API
// frequently omits the version for an onboarded service; if onboarding were keyed off the version
// map, such a service would be misclassified as NEW and re-sent to the add/update-services
// endpoint, which rejects an already-onboarded, non-upgrade service with 501 FEATURE_NOT_IMPLEMENTED.
//
// Here dpa is onboarded but has no version in current.Versions, and the desired input leaves it
// unchanged (no version, no resources), so it must NOT be sent; sca is brand-new and must be sent.
func TestManualClient_UpdateServicesWithReconcile_OnboardedServiceWithoutVersionIsNotResent(t *testing.T) {
	var addedServices []ccemodels.IdsecCCEServiceInput

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		createPostMock(captureAddedServices(&addedServices)),
	})
	defer cleanup()

	manual := newTestManualClient(client)

	current := &CurrentServiceState{
		Names: []string{string(ccemodels.DPA)},
	}
	desired := []ccemodels.IdsecCCEServiceInput{
		{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
		{ServiceName: ccemodels.SCA, Resources: map[string]interface{}{}},
	}

	err := manual.UpdateServicesWithReconcile("test-id", current, desired, "management_group")

	require.NoError(t, err)
	assertServiceNames(t, addedServices, string(ccemodels.SCA))
}

// TestManualClient_UpdateServicesWithReconcile_RemovesUndesiredServices verifies that removal
// stays purely name-based: a service present in current.Names but absent from the desired list is
// removed, regardless of version/resources state.
func TestManualClient_UpdateServicesWithReconcile_RemovesUndesiredServices(t *testing.T) {
	var deletedServices []string

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		createDeleteMock(captureDeletedServices(&deletedServices)),
	})
	defer cleanup()

	manual := newTestManualClient(client)

	current := &CurrentServiceState{
		Names:    []string{string(ccemodels.DPA), string(ccemodels.SCA)},
		Versions: map[string]string{string(ccemodels.DPA): "0.0.3", string(ccemodels.SCA): "0.0.3"},
	}
	desired := []ccemodels.IdsecCCEServiceInput{
		{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]interface{}{}},
	}

	err := manual.UpdateServicesWithReconcile("test-id", current, desired, "entra")

	require.NoError(t, err)
	assertStringSliceContains(t, deletedServices, string(ccemodels.SCA))
}

// TestManualClient_UpdateServicesWithReconcile_NoChanges verifies no API calls are made when the
// desired services exactly match the current deployed state (same versions and resources).
func TestManualClient_UpdateServicesWithReconcile_NoChanges(t *testing.T) {
	postCalled := false
	deleteCalled := false

	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" {
					postCalled = true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "DELETE" {
					deleteCalled = true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	manual := newTestManualClient(client)

	current := &CurrentServiceState{
		Names:    []string{string(ccemodels.DPA), string(ccemodels.SCA)},
		Versions: map[string]string{string(ccemodels.DPA): "0.0.3", string(ccemodels.SCA): "0.0.4"},
		Parameters: map[string]map[string]interface{}{
			string(ccemodels.DPA): {"app_id": "app-123"},
			string(ccemodels.SCA): {"role_arn": "arn:aws:iam::123456789012:role/ScaRole"},
		},
	}
	desired := []ccemodels.IdsecCCEServiceInput{
		{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]interface{}{"appId": "app-123"}},
		{ServiceName: ccemodels.SCA, Version: "0.0.4", Resources: map[string]interface{}{"roleArn": "arn:aws:iam::123456789012:role/ScaRole"}},
	}

	err := manual.UpdateServicesWithReconcile("test-id", current, desired, "management_group")

	require.NoError(t, err)
	require.False(t, postCalled, "POST should not be called when no service changed")
	require.False(t, deleteCalled, "DELETE should not be called when no service was removed")
}

// TestServiceParamsChanged_UnsetOptionalIsNotAChange reproduces the regression that caused a 501
// FEATURE_NOT_IMPLEMENTED on an add-services call. When SCA is onboarded with SSO disabled, the module
// emits `ssoRegion = null`. On the desired side that key survives (as nil) while the stored/API side drops
// it, so a naive "desired key missing from current => changed" check would re-send the unchanged SCA
// service and trip the add-services feature gate. An unset optional value must NOT be treated as a
// change.
//
// ServiceParamsChanged is the single, platform-agnostic home for this comparison (shared by AWS, Azure,
// GCP, ...), so this fix and its coverage apply to every CCE platform, not just the one that first hit it.
func TestServiceParamsChanged_UnsetOptionalIsNotAChange(t *testing.T) {
	// desired uses the caller's key casing (camelCase); ServiceParamsChanged normalizes to snake_case.
	desired := map[string]interface{}{
		"scaPowerRoleArn":    "arn:aws:iam::107760995777:role/SCARole",
		"ssoEnable":          "false",
		"ssoRegion":          nil, // SSO disabled -> unset optional
		"sca_service_region": "us-east-1",
	}
	// current is what the API GET returns (snake_case), with the unset optional dropped.
	current := map[string]interface{}{
		"sca_power_role_arn": "arn:aws:iam::107760995777:role/SCARole",
		"sso_enable":         "false",
		"sca_service_region": "us-east-1",
	}

	require.False(t, ServiceParamsChanged(desired, current),
		"an unchanged service whose only 'diff' is an unset optional (ssoRegion=null) must not be re-sent")
}

// TestServiceParamsChanged_EmptyStringAndCollectionsAreNotChanges guards the other empty-value shapes.
func TestServiceParamsChanged_EmptyStringAndCollectionsAreNotChanges(t *testing.T) {
	desired := map[string]interface{}{
		"presentKey": "value",
		"emptyStr":   "",
		"emptyMap":   map[string]interface{}{},
		"emptyList":  []interface{}{},
	}
	current := map[string]interface{}{
		"present_key": "value",
	}

	require.False(t, ServiceParamsChanged(desired, current),
		"empty-valued desired keys absent from current must not count as a change")
}

// TestServiceParamsChanged_RealValueChangeDetected ensures the hardening does not suppress genuine changes.
func TestServiceParamsChanged_RealValueChangeDetected(t *testing.T) {
	desired := map[string]interface{}{"scaPowerRoleArn": "arn:aws:iam::111111111111:role/New"}
	current := map[string]interface{}{"sca_power_role_arn": "arn:aws:iam::222222222222:role/Old"}

	require.True(t, ServiceParamsChanged(desired, current),
		"a changed value on a shared key must be detected as a change")
}

// TestServiceParamsChanged_NonEmptyKeyMissingIsChange ensures a newly-set (non-empty) key that the current
// state lacks is still treated as a change.
func TestServiceParamsChanged_NonEmptyKeyMissingIsChange(t *testing.T) {
	desired := map[string]interface{}{"ssoRegion": "us-east-2"}
	current := map[string]interface{}{}

	require.True(t, ServiceParamsChanged(desired, current),
		"a non-empty desired key missing from current must be treated as a change")
}

func TestIsEmptyParamValue(t *testing.T) {
	empty := []interface{}{
		nil,
		"",
		map[string]interface{}{},
		[]interface{}{},
	}
	for _, v := range empty {
		require.True(t, IsEmptyParamValue(v), "expected %#v to be empty", v)
	}

	nonEmpty := []interface{}{
		"false",
		"value",
		0,
		false,
		map[string]interface{}{"k": "v"},
		[]interface{}{"a"},
	}
	for _, v := range nonEmpty {
		require.False(t, IsEmptyParamValue(v), "expected %#v to be non-empty", v)
	}
}
