package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// Helper functions to reduce code duplication

// captureAddedServices returns a callback that captures services from POST request body
func captureAddedServices(capturedServices *[]ccemodels.IdsecCCEServiceInput) func(*http.Request) {
	return func(r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var requestData map[string]interface{}
		json.Unmarshal(body, &requestData)
		if services, ok := requestData["services"].([]interface{}); ok {
			for _, svc := range services {
				svcBytes, _ := json.Marshal(svc)
				var service ccemodels.IdsecCCEServiceInput
				json.Unmarshal(svcBytes, &service)
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
func createPostMock(onRequest func(*http.Request)) internal.MockEndpointConfig {
	return internal.MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "POST" && r.URL.Path == "/api/azure/manual/test-id/services"
		},
		StatusCode:   http.StatusOK,
		ResponseBody: `{}`,
		OnRequest:    onRequest,
	}
}

// createDeleteMock creates a standard DELETE mock configuration
func createDeleteMock(onRequest func(*http.Request)) internal.MockEndpointConfig {
	return internal.MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/test-id/services"
		},
		StatusCode:   http.StatusOK,
		ResponseBody: `{}`,
		OnRequest:    onRequest,
	}
}

// createErrorPostMock creates a POST mock that returns an error
func createErrorPostMock(statusCode int, errorBody string) internal.MockEndpointConfig {
	return internal.MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "POST" && r.URL.Path == "/api/azure/manual/test-id/services"
		},
		StatusCode:   statusCode,
		ResponseBody: errorBody,
	}
}

// createErrorDeleteMock creates a DELETE mock that returns an error
func createErrorDeleteMock(statusCode int, errorBody string) internal.MockEndpointConfig {
	return internal.MockEndpointConfig{
		Matcher: func(r *http.Request) bool {
			return r.Method == "DELETE" && r.URL.Path == "/api/azure/manual/test-id/services"
		},
		StatusCode:   statusCode,
		ResponseBody: errorBody,
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

// TestUpdateManualServices_ServiceChanges tests various service change scenarios
func TestUpdateManualServices_ServiceChanges(t *testing.T) {
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

			mocks := []internal.MockEndpointConfig{}
			if len(tt.expectAdded) > 0 {
				mocks = append(mocks, createPostMock(captureAddedServices(&addedServices)))
			}
			if len(tt.expectDeleted) > 0 {
				mocks = append(mocks, createDeleteMock(captureDeletedServices(&deletedServices)))
			}

			client, cleanup := internal.SetupMockCCEService(t, mocks)
			defer cleanup()

			service := setupAzureService(client)
			err := service.updateManualServices("test-id", tt.current, tt.desired, "entra")

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

// TestUpdateManualServices_NoChanges tests scenarios where no API calls should be made
func TestUpdateManualServices_NoChanges(t *testing.T) {
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

			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
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

			service := setupAzureService(client)
			err := service.updateManualServices("test-id", tt.current, tt.desired, "management_group")

			require.NoError(t, err)
			require.False(t, postCalled, "POST should not be called when no services to add")
			require.False(t, deleteCalled, "DELETE should not be called when no services to remove")
		})
	}
}
