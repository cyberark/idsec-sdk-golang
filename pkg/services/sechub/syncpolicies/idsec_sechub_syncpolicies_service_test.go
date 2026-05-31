package syncpolicies

import (
	"fmt"
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
	syncpoliciesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/models"
)

// newMockService creates an IdsecSecHubSyncPoliciesService wired to the given test server.
func newMockService(t *testing.T, serverURL string) *IdsecSecHubSyncPoliciesService {
	t.Helper()

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = serverURL

	ispClient := &isp.IdsecISPServiceClient{
		IdsecClient: client,
	}

	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(ispClient))

	return &IdsecSecHubSyncPoliciesService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}

// syncPolicyJSON returns a minimal JSON response body representing a sync policy.
func syncPolicyJSON(id, name string) string {
	return `{
		"id": "` + id + `",
		"name": "` + name + `",
		"description": "test policy",
		"created_at": "2024-01-01T00:00:00.000000",
		"updated_at": "2024-01-02T00:00:00.000000",
		"created_by": "admin@example.com",
		"updated_by": "admin@example.com",
		"source": {"id": "source-1"},
		"target": {"id": "target-1"},
		"filter": {"id": "filter-1"},
		"transformation": {"id": "transform-1"},
		"state": {"current": "ENABLED"},
		"status": {}
	}`
}

func TestCreate_RetryGetAfterPost(t *testing.T) {
	policyID := "policy-abc-123"
	policyName := "test-sync-policy"

	tests := []struct {
		name             string
		getFailCount     int
		getStatusOnFail  int
		getBodyOnFail    string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *syncpoliciesmodels.IdsecSecHubPolicy)
	}{
		{
			name:            "success_get_succeeds_on_first_attempt",
			getFailCount:    0,
			getStatusOnFail: 0,
			expectedError:   false,
			validateFunc: func(t *testing.T, result *syncpoliciesmodels.IdsecSecHubPolicy) {
				require.NotNil(t, result)
				require.Equal(t, policyID, result.ID)
				require.Equal(t, policyName, result.Name)
				require.Equal(t, "password_only_plain_text", result.Transformation.Predefined)
				require.Equal(t, "transform-1", result.Transformation.ID)
			},
		},
		{
			name:            "success_get_fails_then_succeeds_on_retry",
			getFailCount:    2,
			getStatusOnFail: http.StatusInternalServerError,
			getBodyOnFail:   `{"error": "temporary server error"}`,
			expectedError:   false,
			validateFunc: func(t *testing.T, result *syncpoliciesmodels.IdsecSecHubPolicy) {
				require.NotNil(t, result)
				require.Equal(t, policyID, result.ID)
				require.Equal(t, policyName, result.Name)
			},
		},
		{
			name:            "success_get_fails_then_succeeds_on_last_retry",
			getFailCount:    3, // fails 3 times, succeeds on 4th (last) attempt
			getStatusOnFail: http.StatusServiceUnavailable,
			getBodyOnFail:   `{"error": "service unavailable"}`,
			expectedError:   false,
			validateFunc: func(t *testing.T, result *syncpoliciesmodels.IdsecSecHubPolicy) {
				require.NotNil(t, result)
				require.Equal(t, policyID, result.ID)
			},
		},
		{
			name:             "error_get_fails_all_retries_exhausted",
			getFailCount:     10, // more than max retries
			getStatusOnFail:  http.StatusInternalServerError,
			getBodyOnFail:    `{"error": "persistent server error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get sync policy",
		},
		{
			name:             "error_get_returns_404_all_retries",
			getFailCount:     10,
			getStatusOnFail:  http.StatusNotFound,
			getBodyOnFail:    `{"error": "policy not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get sync policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var getCallCount int
			var mu sync.Mutex

			// Dynamic handler that tracks GET call count to simulate transient failures
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				if r.Method == "POST" && r.URL.Path == sechubURL {
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(syncPolicyJSON(policyID, policyName)))
					return
				}

				if r.Method == "GET" && strings.Contains(r.URL.Path, policyID) {
					mu.Lock()
					currentCount := getCallCount
					getCallCount++
					mu.Unlock()

					if currentCount < tt.getFailCount {
						w.WriteHeader(tt.getStatusOnFail)
						_, _ = w.Write([]byte(tt.getBodyOnFail))
						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(syncPolicyJSON(policyID, policyName)))
					return
				}

				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "endpoint not found"}`))
			}))
			defer testServer.Close()

			svc := newMockService(t, testServer.URL)

			// Execute Create
			result, err := svc.Create(&syncpoliciesmodels.IdsecSechubCreateSyncPolicy{
				Name:        policyName,
				Description: "test policy",
				Source:      syncpoliciesmodels.IdsecSecHubPolicyStore{ID: "source-1"},
				Target:      syncpoliciesmodels.IdsecSecHubPolicyStore{ID: "target-1"},
				Filter:      syncpoliciesmodels.IdsecSecHubPolicyFilter{ID: "filter-1"},
				Transformation: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
					Predefined: "password_only_plain_text",
				},
			})

			// Validate error expectation
			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				// Same text as Logger.Error must bubble to Terraform (full operator guidance + id).
				require.Contains(t, err.Error(), policyID,
					"error from exhausted GET retries must include the created sync policy id from the POST response")
				require.Contains(t, err.Error(), "please use id ["+policyID+"] to retrieve the created sync policy when the service becomes available again")
				require.Nil(t, result)
				return
			}

			// Validate success
			require.NoError(t, err)
			require.NotNil(t, result)

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}

			// Verify GET was called the expected number of times
			mu.Lock()
			finalGetCount := getCallCount
			mu.Unlock()
			expectedGetCalls := tt.getFailCount + 1
			require.Equal(t, expectedGetCalls, finalGetCount,
				"Expected GET to be called %d times (fail=%d + success=1), got %d",
				expectedGetCalls, tt.getFailCount, finalGetCount)
		})
	}
}

func Test_mergeKnownPredefined(t *testing.T) {
	const (
		transformID = "transform-1"
		predefined  = "password_only_plain_text"
	)

	tests := []struct {
		name            string
		response        syncpoliciesmodels.IdsecSecHubPolicyTransformation
		knownPredefined string
		expected        syncpoliciesmodels.IdsecSecHubPolicyTransformation
	}{
		{
			name: "success_merges_non_empty_known_predefined",
			response: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID: transformID,
			},
			knownPredefined: predefined,
			expected: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID:         transformID,
				Predefined: predefined,
			},
		},
		{
			name: "success_leaves_response_unchanged_when_known_predefined_empty",
			response: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID:         transformID,
				Predefined: "",
			},
			knownPredefined: "",
			expected: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID:         transformID,
				Predefined: "",
			},
		},
		{
			name: "success_overwrites_existing_predefined_on_response",
			response: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID:         transformID,
				Predefined: "stale_value",
			},
			knownPredefined: predefined,
			expected: syncpoliciesmodels.IdsecSecHubPolicyTransformation{
				ID:         transformID,
				Predefined: predefined,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := mergeKnownPredefined(tt.response, tt.knownPredefined)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestGet_MergeTransformationPredefined(t *testing.T) {
	const (
		policyID   = "policy-merge-789"
		policyName = "merge-predefined-policy"
		predefined = "password_only_plain_text"
	)

	tests := []struct {
		name                string
		requestPredefined   string
		expectedPredefined  string
		expectedTransformID string
	}{
		{
			name:                "success_merges_non_empty_predefined_from_get_request",
			requestPredefined:   predefined,
			expectedPredefined:  predefined,
			expectedTransformID: "transform-1",
		},
		{
			name:                "success_leaves_predefined_empty_when_get_request_omits_it",
			requestPredefined:   "",
			expectedPredefined:  "",
			expectedTransformID: "transform-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, policyID) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(syncPolicyJSON(policyID, policyName)))
					return
				}
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "endpoint not found"}`))
			}))
			defer testServer.Close()

			svc := newMockService(t, testServer.URL)

			getReq := &syncpoliciesmodels.IdsecSecHubGetSyncPolicy{PolicyID: policyID}
			if tt.requestPredefined != "" {
				getReq.Transformation = syncpoliciesmodels.IdsecSecHubPolicyTransformation{
					Predefined: tt.requestPredefined,
				}
			}

			result, err := svc.Get(getReq)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.expectedPredefined, result.Transformation.Predefined)
			require.Equal(t, tt.expectedTransformID, result.Transformation.ID)
		})
	}
}

func TestDelete_RetryDeleteRequest(t *testing.T) {
	policyID := "policy-del-456"

	tests := []struct {
		name             string
		deleteFailCount  int
		deleteStatusFail int
		deleteBodyFail   string
		disableStatus    int
		disableBody      string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:            "success_delete_succeeds_on_first_attempt",
			deleteFailCount: 0,
			disableStatus:   http.StatusOK,
			disableBody:     `{}`,
			expectedError:   false,
		},
		{
			name:             "success_delete_fails_once_then_succeeds",
			deleteFailCount:  1,
			deleteStatusFail: http.StatusInternalServerError,
			deleteBodyFail:   `{"error": "temporary server error"}`,
			disableStatus:    http.StatusOK,
			disableBody:      `{}`,
			expectedError:    false,
		},
		{
			name:             "success_delete_fails_then_succeeds_on_last_retry",
			deleteFailCount:  3, // fails 3 times, succeeds on 4th (last) attempt
			deleteStatusFail: http.StatusServiceUnavailable,
			deleteBodyFail:   `{"error": "service unavailable"}`,
			disableStatus:    http.StatusOK,
			disableBody:      `{}`,
			expectedError:    false,
		},
		{
			name:             "error_delete_fails_all_retries_exhausted",
			deleteFailCount:  10,
			deleteStatusFail: http.StatusInternalServerError,
			deleteBodyFail:   `{"error": "persistent server error"}`,
			disableStatus:    http.StatusOK,
			disableBody:      `{}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete sync policy",
		},
		{
			name:            "success_delete_succeeds_when_already_disabled",
			deleteFailCount: 0,
			disableStatus:   http.StatusConflict,
			disableBody:     `{"code":"PLCY0006E","message":"Conflict with current policy state"}`,
			expectedError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var deleteCallCount int
			var mu sync.Mutex

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				// PUT /api/policies/{id}/state — disable (SetState)
				if r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/state") {
					w.WriteHeader(tt.disableStatus)
					_, _ = w.Write([]byte(tt.disableBody))
					return
				}

				// DELETE /api/policies/{id}
				if r.Method == "DELETE" && r.URL.Path == fmt.Sprintf(policyURL, policyID) {
					mu.Lock()
					currentCount := deleteCallCount
					deleteCallCount++
					mu.Unlock()

					if currentCount < tt.deleteFailCount {
						w.WriteHeader(tt.deleteStatusFail)
						_, _ = w.Write([]byte(tt.deleteBodyFail))
						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{}`))
					return
				}

				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error": "endpoint not found"}`))
			}))
			defer testServer.Close()

			svc := newMockService(t, testServer.URL)

			err := svc.Delete(&syncpoliciesmodels.IdsecSecHubDeleteSyncPolicy{
				PolicyID: policyID,
			})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)

			// Verify DELETE was called the expected number of times
			mu.Lock()
			finalDeleteCount := deleteCallCount
			mu.Unlock()
			expectedDeleteCalls := tt.deleteFailCount + 1
			require.Equal(t, expectedDeleteCalls, finalDeleteCount,
				"Expected DELETE to be called %d times (fail=%d + success=1), got %d",
				expectedDeleteCalls, tt.deleteFailCount, finalDeleteCount)
		})
	}
}
