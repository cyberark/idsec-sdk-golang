package secretsonboarding

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sechubinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/internal"
	onboardingmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretsonboarding/models"
)

// newMockSecretOnboardingService creates an IdsecSecHubSecretOnboardingService wired to a
// mock HTTP server with the given endpoint configs.
func newMockSecretOnboardingService(t *testing.T, configs []sechubinternal.MockEndpointConfig) (*IdsecSecHubSecretOnboardingService, func()) {
	t.Helper()
	ispClient, cleanup := sechubinternal.SetupMockSecHubService(t, configs)
	ispBase := &services.IdsecISPBaseService{}
	sechubinternal.InjectISPClient(ispBase, ispClient)
	return &IdsecSecHubSecretOnboardingService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}, cleanup
}

func TestIdsecSecHubSecretOnboardingService_Create(t *testing.T) {
	t.Parallel()

	baseReq := &onboardingmodels.IdsecSecHubOnboardSecret{
		SourceStoreType: "AWS_ASM",
		TargetStoreType: "PAM_PCLOUD",
		SecretID:        "secret-a94a8fe5-ccb1-9ba6-1c4c-0873d391e987982fbbd3",
		SecretValueType: "PLAINTEXT",
		SafeName:        "my-safe",
		PamAccount: onboardingmodels.IdsecSecHubOnboardingPamAccount{
			Name:       "accountName",
			PlatformID: "WinServerLocal",
		},
	}

	tests := []struct {
		name        string
		req         *onboardingmodels.IdsecSecHubOnboardSecret
		configs     []sechubinternal.MockEndpointConfig
		expectError bool
	}{
		{
			name: "success_204",
			req:  baseReq,
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "POST" &&
							strings.Contains(r.URL.Path, "AWS_ASM") &&
							strings.Contains(r.URL.Path, "PAM_PCLOUD")
					},
					StatusCode:   http.StatusNoContent,
					ResponseBody: "",
				},
			},
			expectError: false,
		},
		{
			name: "success_with_properties",
			req: &onboardingmodels.IdsecSecHubOnboardSecret{
				SourceStoreType: "AWS_ASM",
				TargetStoreType: "PAM_PCLOUD",
				SecretID:        "secret-a94a8fe5-ccb1-9ba6-1c4c-0873d391e987982fbbd3",
				SecretValueType: "JSON",
				SafeName:        "my-safe",
				PamAccount: onboardingmodels.IdsecSecHubOnboardingPamAccount{
					Name:       "accountName",
					PlatformID: "WinServerLocal",
					Properties: map[string]onboardingmodels.IdsecSecHubOnboardingPamAccountProperty{
						"username": {Type: "VALUE", Value: "example username"},
						"address":  {Type: "VALUE", Value: "example address"},
						"port":     {Type: "KEY_REF", KeyRef: "port_key_in_secret"},
						"password": {Type: "KEY_REF", KeyRef: "password_key_in_secret"},
					},
				},
			},
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "POST" &&
							strings.Contains(r.URL.Path, "AWS_ASM") &&
							strings.Contains(r.URL.Path, "PAM_PCLOUD")
					},
					StatusCode:   http.StatusNoContent,
					ResponseBody: "",
					OnRequest: func(r *http.Request) {
						// Verify the URL path is exactly what the API expects.
						require.Equal(t, "/api/secrets-onboarding/AWS_ASM/PAM_PCLOUD", r.URL.Path,
							"URL path must contain both store type segments in the right positions")

						body, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						bodyStr := string(body)

						// Verify SerializeJSONCamel produced camelCase keys — not snake_case.
						require.Contains(t, bodyStr, `"secretId"`, "secret_id must be serialized as secretId")
						require.Contains(t, bodyStr, `"secretValueType"`, "secret_value_type must be serialized as secretValueType")
						require.Contains(t, bodyStr, `"safeName"`, "safe_name must be serialized as safeName")
						require.Contains(t, bodyStr, `"pamAccount"`, "pam_account must be serialized as pamAccount")
						require.Contains(t, bodyStr, `"platformId"`, "platform_id must be serialized as platformId")
						require.Contains(t, bodyStr, `"keyRef"`, "key_ref must be serialized as keyRef")

						// Verify path params are NOT in the body.
						require.NotContains(t, bodyStr, `"sourceStoreType"`, "sourceStoreType (json:\"-\") must not appear in the body")
						require.NotContains(t, bodyStr, `"targetStoreType"`, "targetStoreType (json:\"-\") must not appear in the body")
					},
				},
			},
			expectError: false,
		},
		{
			name: "error_400_bad_request",
			req:  baseReq,
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "POST" &&
							strings.Contains(r.URL.Path, "AWS_ASM") &&
							strings.Contains(r.URL.Path, "PAM_PCLOUD")
					},
					StatusCode:   http.StatusBadRequest,
					ResponseBody: `{"code":"SSAS0001E","message":"Bad Request"}`,
				},
			},
			expectError: true,
		},
		{
			name: "error_409_conflict",
			req:  baseReq,
			configs: []sechubinternal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == "POST" &&
							strings.Contains(r.URL.Path, "AWS_ASM") &&
							strings.Contains(r.URL.Path, "PAM_PCLOUD")
					},
					StatusCode:   http.StatusConflict,
					ResponseBody: `{"code":"SSAS0002E","message":"Account name already exists"}`,
				},
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, cleanup := newMockSecretOnboardingService(t, tc.configs)
			defer cleanup()

			result, err := svc.Create(tc.req)

			if tc.expectError {
				require.Error(t, err)
				require.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.req, result, "Create must echo back the input request as state")
			}
		})
	}
}
