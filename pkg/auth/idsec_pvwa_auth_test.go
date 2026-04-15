package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestNewIdsecPVWAAuth(t *testing.T) {
	tests := []struct {
		name                string
		cacheAuthentication bool
		validateFunc        func(t *testing.T, result IdsecAuth)
	}{
		{
			name:                "success_with_caching_enabled",
			cacheAuthentication: true,
			validateFunc: func(t *testing.T, result IdsecAuth) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecPVWAAuth")
				}
				pvwaAuth, ok := result.(*IdsecPVWAAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecPVWAAuth")
				}
				if !pvwaAuth.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be true")
				}
				if pvwaAuth.CacheKeyring == nil {
					t.Errorf("Expected CacheKeyring to be initialized")
				}
			},
		},
		{
			name:                "success_with_caching_disabled",
			cacheAuthentication: false,
			validateFunc: func(t *testing.T, result IdsecAuth) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecPVWAAuth")
				}
				pvwaAuth, ok := result.(*IdsecPVWAAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecPVWAAuth")
				}
				if pvwaAuth.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be false")
				}
				if pvwaAuth.CacheKeyring != nil {
					t.Errorf("Expected CacheKeyring to be nil")
				}
			},
		},
		{
			name:                "success_authenticator_initialized",
			cacheAuthentication: true,
			validateFunc: func(t *testing.T, result IdsecAuth) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecPVWAAuth")
				}
				pvwaAuth, ok := result.(*IdsecPVWAAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecPVWAAuth")
				}
				if pvwaAuth.IdsecAuthBase == nil {
					t.Errorf("Expected IdsecAuthBase to be initialized")
				}
				if pvwaAuth.Logger == nil {
					t.Errorf("Expected Logger to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewIdsecPVWAAuth(tt.cacheAuthentication)

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecPVWAAuth_AuthenticatorName(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "success_returns_pvwa_name",
			expectedResult: "pvwa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := NewIdsecPVWAAuth(false)
			result := auth.AuthenticatorName()

			if result != tt.expectedResult {
				t.Errorf("Expected '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecPVWAAuth_AuthenticatorHumanReadableName(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "success_returns_human_readable_name",
			expectedResult: "Password Vault Web Access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := NewIdsecPVWAAuth(false)
			result := auth.AuthenticatorHumanReadableName()

			if result != tt.expectedResult {
				t.Errorf("Expected '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecPVWAAuth_SupportedAuthMethods(t *testing.T) {
	tests := []struct {
		name            string
		expectedMethods []auth.IdsecAuthMethod
	}{
		{
			name: "success_returns_pvwa_method",
			expectedMethods: []auth.IdsecAuthMethod{
				auth.PVWA,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecPVWAAuth(false)
			result := authInstance.SupportedAuthMethods()

			if len(result) != len(tt.expectedMethods) {
				t.Errorf("Expected %d methods, got %d", len(tt.expectedMethods), len(result))
				return
			}

			for i, method := range tt.expectedMethods {
				if result[i] != method {
					t.Errorf("Expected method[%d] to be %s, got %s", i, method, result[i])
				}
			}
		})
	}
}

func TestIdsecPVWAAuth_DefaultAuthMethod(t *testing.T) {
	tests := []struct {
		name                 string
		expectedMethod       auth.IdsecAuthMethod
		expectedSettingsType string
	}{
		{
			name:                 "success_returns_pvwa_method_with_settings",
			expectedMethod:       auth.PVWA,
			expectedSettingsType: "auth.PVWAIdsecAuthMethodSettings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecPVWAAuth(false)
			method, settings := authInstance.DefaultAuthMethod()

			if method != tt.expectedMethod {
				t.Errorf("Expected method %s, got %s", tt.expectedMethod, method)
			}

			if settings == nil {
				t.Errorf("Expected non-nil settings")
				return
			}

			_, ok := settings.(auth.PVWAIdsecAuthMethodSettings)
			if !ok {
				t.Errorf("Expected settings to be of type PVWAIdsecAuthMethodSettings")
			}
		})
	}
}

func TestIdsecPVWAAuth_performAuthentication(t *testing.T) {
	logonPath := "/PasswordVault/API/auth/cyberark/Logon/"

	tests := []struct {
		name             string
		profile          *models.IdsecProfile
		authProfile      *auth.IdsecAuthProfile
		secret           *auth.IdsecSecret
		force            bool
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *auth.IdsecToken)
		setupServer      func(t *testing.T) (profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, cleanup func())
	}{
		{
			name:    "error_unsupported_auth_method",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.Identity,
				AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{
					IdentityURL:             "https://identity.example.com",
					IdentityTenantSubdomain: "tenant",
				},
			},
			secret:           &auth.IdsecSecret{Secret: "password"},
			force:            false,
			expectedError:    true,
			expectedErrorMsg: "given auth method is not supported",
		},
		{
			name:    "error_pvwa_without_secret",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.PVWA,
				AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
					PVWAURL:         "https://pvwa.example.com",
					PVWALoginMethod: auth.PVWALoginMethodCyberArk,
				},
			},
			secret:           nil,
			force:            false,
			expectedError:    true,
			expectedErrorMsg: "password secret is required for PVWA auth",
		},
		{
			name:          "success_pvwa_auth_with_mock_http",
			expectedError: false,
			setupServer: func(t *testing.T) (*models.IdsecProfile, *auth.IdsecAuthProfile, *auth.IdsecSecret, bool, func()) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != logonPath || r.Method != http.MethodPost {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode("mock-pvwa-token")
				}))
				config.DisableCertificateVerification()
				authProfile := &auth.IdsecAuthProfile{
					Username:   "pvwauser",
					AuthMethod: auth.PVWA,
					AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
						PVWAURL:         server.URL,
						PVWALoginMethod: auth.PVWALoginMethodCyberArk,
					},
				}
				return nil, authProfile, &auth.IdsecSecret{Secret: "mypass"}, true, func() {
					server.Close()
					config.EnableCertificateVerification()
				}
			},
			validateFunc: func(t *testing.T, result *auth.IdsecToken) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "mock-pvwa-token" {
					t.Errorf("Expected Token 'mock-pvwa-token', got '%s'", result.Token)
				}
				if result.Username != "pvwauser" {
					t.Errorf("Expected Username 'pvwauser', got '%s'", result.Username)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			profile := tt.profile
			authProfile := tt.authProfile
			secret := tt.secret
			force := tt.force
			if tt.setupServer != nil {
				var cleanup func()
				profile, authProfile, secret, force, cleanup = tt.setupServer(t)
				if cleanup != nil {
					defer cleanup()
				}
			}

			authInstance := NewIdsecPVWAAuth(false).(*IdsecPVWAAuth)
			result, err := authInstance.performAuthentication(profile, authProfile, secret, force)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecPVWAAuth_performRefreshAuthentication(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		authProfile   *auth.IdsecAuthProfile
		token         *auth.IdsecToken
		expectedError bool
		validateFunc  func(t *testing.T, result *auth.IdsecToken)
	}{
		{
			name:    "success_returns_same_token",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.PVWA,
				AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
					PVWAURL:         "https://pvwa.example.com",
					PVWALoginMethod: auth.PVWALoginMethodCyberArk,
				},
			},
			token: &auth.IdsecToken{
				Token:      "existing_token",
				TokenType:  auth.Token,
				Username:   "user1",
				Endpoint:   "https://pvwa.example.com",
				AuthMethod: auth.PVWA,
				ExpiresIn:  common.IdsecRFC3339Time(futureTime),
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "existing_token" {
					t.Errorf("Expected token 'existing_token', got '%s'", result.Token)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecPVWAAuth(false).(*IdsecPVWAAuth)
			result, err := authInstance.performRefreshAuthentication(tt.profile, tt.authProfile, tt.token)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecPVWAAuth_LoadAuthentication(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		refreshAuth   bool
		setupMock     func(auth *IdsecPVWAAuth)
		expectedError bool
		validateFunc  func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecPVWAAuth)
	}{
		{
			name:        "success_loads_from_base_implementation",
			profile:     CreateTestProfile("test", "pvwa", "user1"),
			refreshAuth: false,
			setupMock: func(authInstance *IdsecPVWAAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("cached_token", futureTime, ""), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
				authInstance.CacheAuthentication = true
				authInstance.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.PVWA,
					AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
						PVWAURL:         "https://pvwa.example.com",
						PVWALoginMethod: auth.PVWALoginMethodCyberArk,
					},
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecPVWAAuth) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "cached_token" {
					t.Errorf("Expected 'cached_token', got '%s'", result.Token)
				}
			},
		},
		{
			name:          "success_no_auth_profile_returns_nil",
			profile:       CreateTestProfile("test", "different_auth", "user1"),
			refreshAuth:   false,
			setupMock:     func(authInstance *IdsecPVWAAuth) {},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecPVWAAuth) {
				if result != nil {
					t.Errorf("Expected nil token when no auth profile exists")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecPVWAAuth(false).(*IdsecPVWAAuth)
			if tt.setupMock != nil {
				tt.setupMock(authInstance)
			}

			result, err := authInstance.LoadAuthentication(tt.profile, tt.refreshAuth)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result, authInstance)
			}
		})
	}
}

func TestIdsecPVWAAuth_IsAuthenticated(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	pastTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name           string
		profile        *models.IdsecProfile
		setupMock      func(auth *IdsecPVWAAuth)
		expectedResult bool
	}{
		{
			name:    "success_token_already_loaded",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			setupMock: func(authInstance *IdsecPVWAAuth) {
				authInstance.Token = CreateTestToken("loaded_token", futureTime, "")
			},
			expectedResult: true,
		},
		{
			name:    "success_valid_token_from_cache",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			setupMock: func(authInstance *IdsecPVWAAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("cached_token", futureTime, ""), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
			},
			expectedResult: true,
		},
		{
			name:    "failure_expired_token",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			setupMock: func(authInstance *IdsecPVWAAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("expired_token", pastTime, ""), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
			},
			expectedResult: false,
		},
		{
			name:    "failure_no_auth_profile_for_pvwa",
			profile: CreateTestProfile("test", "different_auth", "user1"),
			setupMock: func(authInstance *IdsecPVWAAuth) {
			},
			expectedResult: false,
		},
		{
			name:    "failure_keyring_load_error",
			profile: CreateTestProfile("test", "pvwa", "user1"),
			setupMock: func(authInstance *IdsecPVWAAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return nil, errors.New("keyring error")
					},
				}
				authInstance.CacheKeyring = mockKeyring
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecPVWAAuth(false).(*IdsecPVWAAuth)
			if tt.setupMock != nil {
				tt.setupMock(authInstance)
			}

			result := authInstance.IsAuthenticated(tt.profile)

			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestPVWADefaultTokenLifetime(t *testing.T) {
	tests := []struct {
		name          string
		expectedValue int
	}{
		{
			name:          "success_default_token_lifetime_is_3600",
			expectedValue: 3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if PVWADefaultTokenLifetime != tt.expectedValue {
				t.Errorf("Expected PVWADefaultTokenLifetime to be %d, got %d", tt.expectedValue, PVWADefaultTokenLifetime)
			}
		})
	}
}

func TestPVWAAuthConstants(t *testing.T) {
	tests := []struct {
		name          string
		constantName  string
		expectedValue string
	}{
		{
			name:          "success_auth_name_is_pvwa",
			constantName:  "pvwaAuthName",
			expectedValue: "pvwa",
		},
		{
			name:          "success_human_readable_name",
			constantName:  "pvwaAuthHumanReadableName",
			expectedValue: "Password Vault Web Access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var actualValue string
			switch tt.constantName {
			case "pvwaAuthName":
				actualValue = pvwaAuthName
			case "pvwaAuthHumanReadableName":
				actualValue = pvwaAuthHumanReadableName
			}

			if actualValue != tt.expectedValue {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.constantName, tt.expectedValue, actualValue)
			}
		})
	}
}

func TestPVWAAuthMethodDefaults(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_default_auth_methods_contains_pvwa",
			validateFunc: func(t *testing.T) {
				if len(pvwaAuthMethods) != 1 {
					t.Errorf("Expected 1 auth method, got %d", len(pvwaAuthMethods))
				}
				if pvwaAuthMethods[0] != auth.PVWA {
					t.Errorf("Expected first method to be PVWA, got %s", pvwaAuthMethods[0])
				}
			},
		},
		{
			name: "success_default_method_is_pvwa",
			validateFunc: func(t *testing.T) {
				if pvwaDefaultAuthMethod != auth.PVWA {
					t.Errorf("Expected default method to be PVWA, got %s", pvwaDefaultAuthMethod)
				}
			},
		},
		{
			name: "success_default_settings_is_pvwa_settings",
			validateFunc: func(t *testing.T) {
				_, ok := interface{}(pvwaDefaultAuthMethodSettings).(auth.PVWAIdsecAuthMethodSettings)
				if !ok {
					t.Errorf("Expected default settings to be PVWAIdsecAuthMethodSettings")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.validateFunc != nil {
				tt.validateFunc(t)
			}
		})
	}
}
