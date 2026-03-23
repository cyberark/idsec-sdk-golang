package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	pkgauth "github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// createTestJWT builds a minimal JWT token with the given claims for testing.
// The signature is a dummy value since ParseUnverified is used in ResolveIdentityServiceURL.
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("dummysignature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

// newTestISPAuth creates an IdsecISPAuth with the given token string for testing.
func newTestISPAuth(token string) *pkgauth.IdsecISPAuth {
	return &pkgauth.IdsecISPAuth{
		IdsecAuthBase: &pkgauth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token: token,
			},
		},
	}
}

func TestResolveIdentityServiceURL(t *testing.T) {
	validJWTWithIss := createTestJWT(map[string]interface{}{
		"iss": "https://identity.example.com/oauth2",
		"sub": "user@example.com",
	})
	validJWTWithoutIss := createTestJWT(map[string]interface{}{
		"sub": "user@example.com",
	})

	tests := []struct {
		name             string
		token            string
		platformURL      string
		envVarValue      string
		expectedResult   string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_falls_back_to_platform_url_when_env_var_set",
			token:          validJWTWithIss,
			platformURL:    "https://platform.example.com",
			envVarValue:    "true",
			expectedResult: "https://platform.example.com",
			expectedError:  false,
		},
		{
			name:           "success_falls_back_to_platform_url_when_token_empty",
			token:          "",
			platformURL:    "https://platform.example.com",
			envVarValue:    "",
			expectedResult: "https://platform.example.com",
			expectedError:  false,
		},
		{
			name:           "success_resolves_url_from_jwt_iss_claim",
			token:          validJWTWithIss,
			platformURL:    "https://platform.example.com",
			envVarValue:    "",
			expectedResult: "https://identity.example.com",
			expectedError:  false,
		},
		{
			name:           "success_platform_url_empty_resolves_from_jwt",
			token:          validJWTWithIss,
			platformURL:    "",
			envVarValue:    "",
			expectedResult: "https://identity.example.com",
			expectedError:  false,
		},
		{
			name:           "success_env_var_and_empty_token_both_trigger_platform_url",
			token:          "",
			platformURL:    "https://platform.example.com",
			envVarValue:    "true",
			expectedResult: "https://platform.example.com",
			expectedError:  false,
		},
		{
			name:          "error_invalid_jwt_token",
			token:         "invalid-jwt-string",
			platformURL:   "",
			envVarValue:   "",
			expectedError: true,
		},
		{
			name:             "error_jwt_missing_iss_claim",
			token:            validJWTWithoutIss,
			platformURL:      "",
			envVarValue:      "",
			expectedError:    true,
			expectedErrorMsg: "failed to parse issuer from token claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tests are not run in parallel because env var manipulation is global state.
			t.Setenv(ForcePlatformURLEnvVar, tt.envVarValue)

			ispAuth := newTestISPAuth(tt.token)
			result, err := ResolveIdentityServiceURL(ispAuth, tt.platformURL)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error message %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result != tt.expectedResult {
				t.Errorf("Expected result %q, got %q", tt.expectedResult, result)
			}
		})
	}
}
