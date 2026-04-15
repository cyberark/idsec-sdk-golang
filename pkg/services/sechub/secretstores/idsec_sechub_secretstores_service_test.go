package secretstores

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	secretstoresmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"
)

// mockEndpointConfig defines configuration for a single endpoint matcher.
type mockEndpointConfig struct {
	Matcher      func(*http.Request) bool
	StatusCode   int
	ResponseBody string
	OnRequest    func(*http.Request)
}

// setupMockSecretStoresService creates a mock HTTP server with the given endpoint configs
// and returns an IdsecSecHubSecretStoresService wired to the mock server.
func setupMockSecretStoresService(t *testing.T, configs []mockEndpointConfig) (*IdsecSecHubSecretStoresService, func()) {
	t.Helper()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		for _, config := range configs {
			if config.Matcher(r) {
				if config.OnRequest != nil {
					config.OnRequest(r)
				}
				w.WriteHeader(config.StatusCode)
				_, _ = w.Write([]byte(config.ResponseBody))
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "endpoint not found in mock configuration"}`))
	}))

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL

	ispClient := &isp.IdsecISPServiceClient{
		IdsecClient: client,
	}

	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(ispClient))

	svc := &IdsecSecHubSecretStoresService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}

	cleanup := func() {
		testServer.Close()
	}

	return svc, cleanup
}

// currentStoreJSON returns a JSON response body representing a secret store with the given state.
func currentStoreJSON(id, name, description, state string) string {
	return `{
		"id": "` + id + `",
		"type": "AWS_ASM",
		"behaviors": ["SECRETS_TARGET"],
		"created_at": "2024-01-01T00:00:00.000000",
		"created_by": "admin@example.com",
		"data": {
			"account_id": "123456789012",
			"region_id": "us-east-1",
			"role_name": "SecretsHubRole"
		},
		"description": "` + description + `",
		"name": "` + name + `",
		"updated_at": "2024-01-02T00:00:00.000000",
		"updated_by": "admin@example.com",
		"scan": {
			"id": "scan-1",
			"status": "SUCCESS"
		},
		"store_status": {
			"status": "SUCCESS",
			"message": "ok"
		},
		"state": "` + state + `"
	}`
}

func TestIdsecSecHubSecretStoresService_UpdateTF_RollbackOnStateChangeFailed(t *testing.T) {
	storeID := "store-abc-123"
	storeName := "my-aws-store"
	storeDescription := "Test secret store"

	tests := []struct {
		name             string
		currentState     string
		desiredState     string
		setStateStatus   int
		setStateBody     string
		rollbackStatus   int
		rollbackBody     string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *secretstoresmodels.IdsecSecHubSecretStore, err error)
	}{
		{
			name:             "rollback_success_when_set_state_fails",
			currentState:     "ENABLED",
			desiredState:     "DISABLED",
			setStateStatus:   http.StatusInternalServerError,
			setStateBody:     `{"error": "internal server error"}`,
			rollbackStatus:   http.StatusOK,
			rollbackBody:     currentStoreJSON(storeID, storeName, storeDescription, "ENABLED"),
			expectedError:    true,
			expectedErrorMsg: "failed to set secret store state for TF update",
			validateFunc: func(t *testing.T, result *secretstoresmodels.IdsecSecHubSecretStore, err error) {
				// Rollback succeeded, so result should be returned with original state
				require.NotNil(t, result)
				require.Equal(t, "ENABLED", result.State)
				require.Equal(t, storeID, result.ID)
				require.Equal(t, storeName, result.Name)
				// Error should NOT contain "rollback failed"
				require.NotContains(t, err.Error(), "rollback failed")
			},
		},
		{
			name:             "rollback_fails_when_set_state_and_update_both_fail",
			currentState:     "ENABLED",
			desiredState:     "DISABLED",
			setStateStatus:   http.StatusInternalServerError,
			setStateBody:     `{"error": "internal server error"}`,
			rollbackStatus:   http.StatusInternalServerError,
			rollbackBody:     `{"error": "rollback also failed"}`,
			expectedError:    true,
			expectedErrorMsg: "rollback failed",
			validateFunc: func(t *testing.T, result *secretstoresmodels.IdsecSecHubSecretStore, err error) {
				// Both SetState and rollback failed, result should be nil
				require.Nil(t, result)
				require.Contains(t, err.Error(), "failed to set secret store state for TF update and rollback failed")
				require.Contains(t, err.Error(), "rollback error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Track PATCH call count to differentiate the update call from the rollback call
			var patchCallCount int
			var mu sync.Mutex

			// The update response (first PATCH) always succeeds
			updatedStoreJSON := currentStoreJSON(storeID, storeName, storeDescription, tt.currentState)

			configs := []mockEndpointConfig{
				{
					// GET /api/secret-stores/{id} — retrieve current store
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && strings.Contains(r.URL.Path, storeID)
					},
					StatusCode:   http.StatusOK,
					ResponseBody: currentStoreJSON(storeID, storeName, storeDescription, tt.currentState),
				},
				{
					// PATCH /api/secret-stores/{id} — update or rollback
					Matcher: func(r *http.Request) bool {
						return r.Method == "PATCH" && strings.Contains(r.URL.Path, storeID)
					},
					StatusCode:   http.StatusOK,
					ResponseBody: updatedStoreJSON,
				},
			}

			// If a state change is expected, add the PUT /state endpoint
			if tt.currentState != tt.desiredState {
				configs = []mockEndpointConfig{
					{
						// GET /api/secret-stores/{id}
						Matcher: func(r *http.Request) bool {
							return r.Method == "GET" && strings.Contains(r.URL.Path, storeID)
						},
						StatusCode:   http.StatusOK,
						ResponseBody: currentStoreJSON(storeID, storeName, storeDescription, tt.currentState),
					},
					{
						// PATCH /api/secret-stores/{id} — first PATCH is update, second is rollback
						Matcher: func(r *http.Request) bool {
							if r.Method != "PATCH" || !strings.Contains(r.URL.Path, storeID) {
								return false
							}
							mu.Lock()
							defer mu.Unlock()
							// First PATCH call (update) always matches here
							if patchCallCount == 0 {
								patchCallCount++
								return true
							}
							return false
						},
						StatusCode:   http.StatusOK,
						ResponseBody: updatedStoreJSON,
					},
					{
						// PUT /api/secret-stores/{id}/state — SetState (configured to fail)
						Matcher: func(r *http.Request) bool {
							return r.Method == "PUT" && strings.Contains(r.URL.Path, "/state")
						},
						StatusCode:   tt.setStateStatus,
						ResponseBody: tt.setStateBody,
					},
					{
						// PATCH /api/secret-stores/{id} — rollback call (second PATCH)
						Matcher: func(r *http.Request) bool {
							if r.Method != "PATCH" || !strings.Contains(r.URL.Path, storeID) {
								return false
							}
							mu.Lock()
							defer mu.Unlock()
							// Second PATCH call (rollback)
							return patchCallCount >= 1
						},
						StatusCode:   tt.rollbackStatus,
						ResponseBody: tt.rollbackBody,
					},
				}
			}

			service, cleanup := setupMockSecretStoresService(t, configs)
			defer cleanup()

			result, err := service.UpdateTf(&secretstoresmodels.IdsecSecHubUpdateTfSecretStore{
				ID:          storeID,
				Name:        storeName,
				Description: storeDescription,
				State:       tt.desiredState,
			})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
			} else {
				require.NoError(t, err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result, err)
			}
		})
	}
}

func TestToAction(t *testing.T) {
	tests := []struct {
		name             string
		state            StoreState
		expectedAction   StoreAction
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_enabled_state",
			state:          StateEnabled,
			expectedAction: ActionEnable,
			expectedError:  false,
		},
		{
			name:           "success_disabled_state",
			state:          StateDisabled,
			expectedAction: ActionDisable,
			expectedError:  false,
		},
		{
			name:             "error_empty_state",
			state:            StoreState(""),
			expectedError:    true,
			expectedErrorMsg: "invalid state: ",
		},
		{
			name:             "error_unknown_state",
			state:            StoreState("UNKNOWN"),
			expectedError:    true,
			expectedErrorMsg: "invalid state: UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action, err := tt.state.toAction()

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.EqualError(t, err, tt.expectedErrorMsg)
				}
				require.Equal(t, StoreAction(""), action)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedAction, action)
		})
	}
}

func TestStripImmutableFields(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "strips_immutable_fields_keeps_mutable",
			input: map[string]interface{}{
				"data": map[string]interface{}{
					"accountId":     "123",
					"regionId":      "us-east-1",
					"azureVaultUrl": "https://vault",
					"hashiVaultUrl": "https://hv",
					"mountPath":     "/secret",
					"name":          "my-store",
				},
			},
			expected: map[string]interface{}{
				"data": map[string]interface{}{
					"name": "my-store",
				},
			},
		},
		{
			name: "no_data_key",
			input: map[string]interface{}{
				"other": "value",
			},
			expected: map[string]interface{}{
				"other": "value",
			},
		},
		{
			name: "empty_data_map",
			input: map[string]interface{}{
				"data": map[string]interface{}{},
			},
			expected: map[string]interface{}{
				"data": map[string]interface{}{},
			},
		}, {
			name: "only_mutable_fields_unchanged",
			input: map[string]interface{}{
				"data": map[string]interface{}{
					"name":        "my-store",
					"description": "AWS_ASM description",
				},
			},
			expected: map[string]interface{}{
				"data": map[string]interface{}{
					"name":        "my-store",
					"description": "AWS_ASM description",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := &IdsecSecHubSecretStoresService{}
			svc.stripImmutableFields(tt.input)

			if !reflect.DeepEqual(tt.input, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, tt.input)
			}
		})
	}
}
