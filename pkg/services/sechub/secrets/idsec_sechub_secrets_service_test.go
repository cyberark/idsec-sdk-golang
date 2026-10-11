package secrets

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/internal"
	secretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets/models"
)

// newMockSecretsService creates an IdsecSecHubSecretsService wired to a mock HTTP server
// with the given endpoint configs.
func newMockSecretsService(t *testing.T, configs []sechubinternal.MockEndpointConfig) (*IdsecSecHubSecretsService, func()) {
	t.Helper()
	ispClient, cleanup := sechubinternal.SetupMockSecHubService(t, configs)
	ispBase := &services.IdsecISPBaseService{}
	sechubinternal.InjectISPClient(ispBase, ispClient)
	return &IdsecSecHubSecretsService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}, cleanup
}

// secretJSON returns a minimal JSON response body representing a single secret.
func secretJSON(name, storeID, status, message string) string {
	return `{"id":"secret-abc123","name":"` + name + `","storeId":"` + storeID + `",` +
		`"vendorType":"AWS","vendorSubType":"ASM",` +
		`"originId":"arn:aws:secretsmanager:us-east-1:123456789012:secret:` + name + `",` +
		`"discoveredAt":"2024-01-01T00:00:00.000Z","lastScannedAt":"2024-01-01T00:00:00.000Z",` +
		`"onboardData":{"status":"` + status + `","message":"` + message + `"}}`
}

func TestIdsecSecHubSecretsService_FindByNameAndStoreId(t *testing.T) {
	t.Parallel()

	req := &secretsmodels.IdsecSecHubFindSecretByNameAndStoreID{
		Name:    "my-secret",
		StoreID: "store-abc",
	}

	tests := []struct {
		name           string
		configs        []sechubinternal.MockEndpointConfig
		expectError    bool
		errorContains  string
		validateSecret func(t *testing.T, secret *secretsmodels.IdsecSecHubSecret)
	}{
		{
			name: "success_candidate",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{"secrets":[` + secretJSON("my-secret", "store-abc", "CANDIDATE", "") + `]}`,
				},
			},
			expectError: false,
			validateSecret: func(t *testing.T, secret *secretsmodels.IdsecSecHubSecret) {
				require.Equal(t, "secret-abc123", secret.ID)
				require.Equal(t, "CANDIDATE", secret.OnboardData.Status)
			},
		},
		{
			name: "success_onboarded",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{"secrets":[` + secretJSON("my-secret", "store-abc", "ONBOARDED", "") + `]}`,
				},
			},
			expectError: false,
			validateSecret: func(t *testing.T, secret *secretsmodels.IdsecSecHubSecret) {
				require.Equal(t, "ONBOARDED", secret.OnboardData.Status)
			},
		},
		{
			name: "error_not_found",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{"secrets":[]}`,
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "error_too_many_secrets",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode: http.StatusOK,
					// Two results with the same name+storeId = true duplicate → too many secrets.
					ResponseBody: `{"secrets":[` +
						secretJSON("my-secret", "store-abc", "CANDIDATE", "") + `,` +
						secretJSON("my-secret", "store-abc", "CANDIDATE", "") +
						`]}`,
				},
			},
			expectError:   true,
			errorContains: "too many secrets",
		},
		{
			name: "success_exact_with_longer_neighbour",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode: http.StatusOK,
					// items[0] is an exact match; items[1] is a lexicographic neighbour — should succeed.
					ResponseBody: `{"secrets":[` +
						secretJSON("my-secret", "store-abc", "CANDIDATE", "") + `,` +
						secretJSON("my-secret-test", "store-abc", "CANDIDATE", "") +
						`]}`,
				},
			},
			expectError: false,
			validateSecret: func(t *testing.T, secret *secretsmodels.IdsecSecHubSecret) {
				require.Equal(t, "my-secret", secret.Name)
			},
		},
		{
			name: "error_first_is_not_exact",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode: http.StatusOK,
					// Neither result matches exactly — secret does not exist in the store.
					ResponseBody: `{"secrets":[` +
						secretJSON("my-secret-prod", "store-abc", "CANDIDATE", "") + `,` +
						secretJSON("my-secret-test", "store-abc", "CANDIDATE", "") +
						`]}`,
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "error_not_candidate_with_message",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{"secrets":[` + secretJSON("my-secret", "store-abc", "NOT_CANDIDATE", "secret type not supported") + `]}`,
				},
			},
			expectError:   true,
			errorContains: "secret type not supported",
		},
		{
			name: "error_contains_only_match",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusOK,
					ResponseBody: `{"secrets":[` + secretJSON("my-secret-something", "store-abc", "CANDIDATE", "") + `]}`,
				},
			},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "error_http_non_200",
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "GET" && r.URL.Path == sechubURL
					},
					StatusCode:   http.StatusInternalServerError,
					ResponseBody: `{"error":"internal server error"}`,
				},
			},
			expectError:   true,
			errorContains: "failed to find secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotFilter string
			for i := range tt.configs {
				original := tt.configs[i].OnRequest
				tt.configs[i].OnRequest = func(r *http.Request) {
					if original != nil {
						original(r)
					}
					filterRaw := r.URL.Query().Get("filter")
					decoded, err := url.QueryUnescape(filterRaw)
					if err != nil {
						decoded = filterRaw
					}
					gotFilter = decoded
					require.Equal(t, "2", r.URL.Query().Get("limit"),
						"limit must be exactly 2: a limit of 1 would silently suppress the ambiguity check")
					require.Equal(t, "name ASC", r.URL.Query().Get("sort"),
						"sort must be name ASC to guarantee lexicographic ordering")
				}
			}

			svc, cleanup := newMockSecretsService(t, tt.configs)
			defer cleanup()

			secret, err := svc.FindByNameAndStoreId(req)

			// Filter assertion runs for all cases — the GET is always sent.
			require.True(t, strings.Contains(gotFilter, `name CONTAINS "my-secret"`),
				"filter should contain name CONTAINS, got: %s", gotFilter)
			require.True(t, strings.Contains(gotFilter, `storeId CONTAINS "store-abc"`),
				"filter should contain storeId CONTAINS, got: %s", gotFilter)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					require.Contains(t, err.Error(), tt.errorContains)
				}
				require.Nil(t, secret)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, secret)
			if tt.validateSecret != nil {
				tt.validateSecret(t, secret)
			}
		})
	}
}
