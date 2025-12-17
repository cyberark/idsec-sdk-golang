package auth

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// MockIdentityAuth is a mock for identity authentication
type MockIdentityAuth struct {
	SessionTokenFunc   func() string
	SessionDetailsFunc func() *MockSessionDetails
	IdentityURLFunc    func() string
	SessionFunc        func() *MockSession
	AuthIdentityFunc   func(profile *models.IdsecProfile, interactive bool, force bool) error
	RefreshAuthFunc    func(profile *models.IdsecProfile, interactive bool, force bool) error
}

// MockSessionDetails mocks session details
type MockSessionDetails struct {
	TokenLifetime int
	RefreshToken  string
}

// MockSession mocks the session object
type MockSession struct {
	CookieJarFunc func() http.CookieJar
}

func (m *MockSession) GetCookieJar() http.CookieJar {
	if m.CookieJarFunc != nil {
		return m.CookieJarFunc()
	}
	jar, _ := cookiejar.New(nil)
	return jar
}

func TestNewIdsecISPAuth(t *testing.T) {
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
					t.Fatal("Expected non-nil IdsecISPAuth")
				}
				ispAuth, ok := result.(*IdsecISPAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecISPAuth")
				}
				if !ispAuth.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be true")
				}
				if ispAuth.CacheKeyring == nil {
					t.Errorf("Expected CacheKeyring to be initialized")
				}
			},
		},
		{
			name:                "success_with_caching_disabled",
			cacheAuthentication: false,
			validateFunc: func(t *testing.T, result IdsecAuth) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecISPAuth")
				}
				ispAuth, ok := result.(*IdsecISPAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecISPAuth")
				}
				if ispAuth.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be false")
				}
				if ispAuth.CacheKeyring != nil {
					t.Errorf("Expected CacheKeyring to be nil")
				}
			},
		},
		{
			name:                "success_authenticator_initialized",
			cacheAuthentication: true,
			validateFunc: func(t *testing.T, result IdsecAuth) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecISPAuth")
				}
				ispAuth, ok := result.(*IdsecISPAuth)
				if !ok {
					t.Fatal("Expected result to be *IdsecISPAuth")
				}
				if ispAuth.IdsecAuthBase == nil {
					t.Errorf("Expected IdsecAuthBase to be initialized")
				}
				if ispAuth.Logger == nil {
					t.Errorf("Expected Logger to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewIdsecISPAuth(tt.cacheAuthentication)

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecISPAuth_AuthenticatorName(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "success_returns_isp_name",
			expectedResult: "isp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := NewIdsecISPAuth(false)
			result := auth.AuthenticatorName()

			if result != tt.expectedResult {
				t.Errorf("Expected '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecISPAuth_AuthenticatorHumanReadableName(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "success_returns_human_readable_name",
			expectedResult: "Identity Security Platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auth := NewIdsecISPAuth(false)
			result := auth.AuthenticatorHumanReadableName()

			if result != tt.expectedResult {
				t.Errorf("Expected '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecISPAuth_SupportedAuthMethods(t *testing.T) {
	tests := []struct {
		name            string
		expectedMethods []auth.IdsecAuthMethod
	}{
		{
			name: "success_returns_identity_and_service_user_methods",
			expectedMethods: []auth.IdsecAuthMethod{
				auth.Identity,
				auth.IdentityServiceUser,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false)
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

func TestIdsecISPAuth_DefaultAuthMethod(t *testing.T) {
	tests := []struct {
		name                 string
		expectedMethod       auth.IdsecAuthMethod
		expectedSettingsType string
	}{
		{
			name:                 "success_returns_identity_method_with_settings",
			expectedMethod:       auth.Identity,
			expectedSettingsType: "auth.IdentityIdsecAuthMethodSettings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false)
			method, settings := authInstance.DefaultAuthMethod()

			if method != tt.expectedMethod {
				t.Errorf("Expected method %s, got %s", tt.expectedMethod, method)
			}

			if settings == nil {
				t.Errorf("Expected non-nil settings")
				return
			}

			_, ok := settings.(auth.IdentityIdsecAuthMethodSettings)
			if !ok {
				t.Errorf("Expected settings to be of type IdentityIdsecAuthMethodSettings")
			}
		})
	}
}

func TestIdsecISPAuth_performAuthentication(t *testing.T) {
	tests := []struct {
		name             string
		profile          *models.IdsecProfile
		authProfile      *auth.IdsecAuthProfile
		secret           *auth.IdsecSecret
		force            bool
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *auth.IdsecToken)
	}{
		{
			name:    "error_unsupported_auth_method",
			profile: CreateTestProfile("test", "isp", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.Direct,
				AuthMethodSettings: &auth.DirectIdsecAuthMethodSettings{
					Endpoint: "https://test.example.com",
				},
			},
			secret:           &auth.IdsecSecret{Secret: "password"},
			force:            false,
			expectedError:    true,
			expectedErrorMsg: "given auth method is not supported",
		},
		{
			name:    "error_identity_service_user_without_secret",
			profile: CreateTestProfile("test", "isp", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.IdentityServiceUser,
				AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
					IdentityURL:                      "https://identity.example.com",
					IdentityTenantSubdomain:          "tenant",
					IdentityAuthorizationApplication: "app",
				},
			},
			secret:           nil,
			force:            false,
			expectedError:    true,
			expectedErrorMsg: "token secret is required for identity service user auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
			result, err := authInstance.performAuthentication(tt.profile, tt.authProfile, tt.secret, tt.force)

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

func TestIdsecISPAuth_performRefreshAuthentication(t *testing.T) {
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
			name:    "success_identity_service_user_returns_same_token",
			profile: CreateTestProfile("test", "isp", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.IdentityServiceUser,
				AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
					IdentityURL:                      "https://identity.example.com",
					IdentityTenantSubdomain:          "tenant",
					IdentityAuthorizationApplication: "app",
				},
			},
			token: &auth.IdsecToken{
				Token:        "existing_token",
				TokenType:    auth.JWT,
				Username:     "user1",
				Endpoint:     "https://identity.example.com",
				AuthMethod:   auth.IdentityServiceUser,
				ExpiresIn:    common.IdsecRFC3339Time(futureTime),
				RefreshToken: "refresh_token",
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

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
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

func TestIdsecISPAuth_LoadAuthentication(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		refreshAuth   bool
		setupMock     func(auth *IdsecISPAuth)
		expectedError bool
		validateFunc  func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecISPAuth)
	}{
		{
			name:        "success_loads_from_base_implementation",
			profile:     CreateTestProfile("test", "isp", "user1"),
			refreshAuth: false,
			setupMock: func(authInstance *IdsecISPAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("cached_token", futureTime, "refresh"), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
				authInstance.CacheAuthentication = true
				authInstance.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Identity,
					AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{
						IdentityURL:             "https://identity.example.com",
						IdentityTenantSubdomain: "tenant",
					},
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecISPAuth) {
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
			setupMock:     func(authInstance *IdsecISPAuth) {},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecISPAuth) {
				if result != nil {
					t.Errorf("Expected nil token when no auth profile exists")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
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

func TestIdsecISPAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name             string
		profile          *models.IdsecProfile
		authProfile      *auth.IdsecAuthProfile
		secret           *auth.IdsecSecret
		force            bool
		refreshAuth      bool
		setupMock        func(auth *IdsecISPAuth)
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *auth.IdsecToken, authInstance *IdsecISPAuth)
	}{
		{
			name:             "error_both_profile_and_auth_profile_nil",
			profile:          nil,
			authProfile:      nil,
			secret:           nil,
			force:            false,
			refreshAuth:      false,
			setupMock:        func(authInstance *IdsecISPAuth) {},
			expectedError:    true,
			expectedErrorMsg: "either a profile or a specific auth profile must be supplied",
		},
		{
			name:        "error_unsupported_auth_method_in_profile",
			profile:     CreateTestProfile("test", "isp", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(authInstance *IdsecISPAuth) {
				// Modify the profile's auth method to be unsupported
				authInstance.ActiveProfile = CreateTestProfile("test", "isp", "user1")
				authInstance.ActiveProfile.AuthProfiles["isp"].AuthMethod = auth.Direct
			},
			expectedError:    true,
			expectedErrorMsg: "Identity Security Platform does not support authentication method direct",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
			if tt.setupMock != nil {
				tt.setupMock(authInstance)
			}

			result, err := authInstance.Authenticate(tt.profile, tt.authProfile, tt.secret, tt.force, tt.refreshAuth)

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
				tt.validateFunc(t, result, authInstance)
			}
		})
	}
}

func TestIdsecISPAuth_IsAuthenticated(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	pastTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name           string
		profile        *models.IdsecProfile
		setupMock      func(auth *IdsecISPAuth)
		expectedResult bool
	}{
		{
			name:    "success_token_already_loaded",
			profile: CreateTestProfile("test", "isp", "user1"),
			setupMock: func(authInstance *IdsecISPAuth) {
				authInstance.Token = CreateTestToken("loaded_token", futureTime, "refresh")
			},
			expectedResult: true,
		},
		{
			name:    "success_valid_token_from_cache",
			profile: CreateTestProfile("test", "isp", "user1"),
			setupMock: func(authInstance *IdsecISPAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("cached_token", futureTime, "refresh"), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
			},
			expectedResult: true,
		},
		{
			name:    "failure_expired_token",
			profile: CreateTestProfile("test", "isp", "user1"),
			setupMock: func(authInstance *IdsecISPAuth) {
				mockKeyring := &MockKeyring{
					LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
						return CreateTestToken("expired_token", pastTime, "refresh"), nil
					},
				}
				authInstance.CacheKeyring = mockKeyring
			},
			expectedResult: false,
		},
		{
			name:    "failure_no_auth_profile_for_isp",
			profile: CreateTestProfile("test", "different_auth", "user1"),
			setupMock: func(authInstance *IdsecISPAuth) {
			},
			expectedResult: false,
		},
		{
			name:    "failure_keyring_load_error",
			profile: CreateTestProfile("test", "isp", "user1"),
			setupMock: func(authInstance *IdsecISPAuth) {
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

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
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

func TestDefaultTokenLifetime(t *testing.T) {
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

			if DefaultTokenLifetime != tt.expectedValue {
				t.Errorf("Expected DefaultTokenLifetime to be %d, got %d", tt.expectedValue, DefaultTokenLifetime)
			}
		})
	}
}

func TestISPAuthConstants(t *testing.T) {
	tests := []struct {
		name          string
		constantName  string
		expectedValue string
	}{
		{
			name:          "success_auth_name_is_isp",
			constantName:  "ispAuthName",
			expectedValue: "isp",
		},
		{
			name:          "success_human_readable_name",
			constantName:  "ispAuthHumanReadableName",
			expectedValue: "Identity Security Platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var actualValue string
			switch tt.constantName {
			case "ispAuthName":
				actualValue = ispAuthName
			case "ispAuthHumanReadableName":
				actualValue = ispAuthHumanReadableName
			}

			if actualValue != tt.expectedValue {
				t.Errorf("Expected %s to be '%s', got '%s'", tt.constantName, tt.expectedValue, actualValue)
			}
		})
	}
}

func TestISPAuthMethodDefaults(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_default_auth_methods_contains_identity_and_service_user",
			validateFunc: func(t *testing.T) {
				if len(ispAuthMethods) != 2 {
					t.Errorf("Expected 2 auth methods, got %d", len(ispAuthMethods))
				}
				if ispAuthMethods[0] != auth.Identity {
					t.Errorf("Expected first method to be Identity, got %s", ispAuthMethods[0])
				}
				if ispAuthMethods[1] != auth.IdentityServiceUser {
					t.Errorf("Expected second method to be IdentityServiceUser, got %s", ispAuthMethods[1])
				}
			},
		},
		{
			name: "success_default_method_is_identity",
			validateFunc: func(t *testing.T) {
				if ispDefaultAuthMethod != auth.Identity {
					t.Errorf("Expected default method to be Identity, got %s", ispDefaultAuthMethod)
				}
			},
		},
		{
			name: "success_default_settings_is_identity_settings",
			validateFunc: func(t *testing.T) {
				_, ok := interface{}(ispDefaultAuthMethodSettings).(auth.IdentityIdsecAuthMethodSettings)
				if !ok {
					t.Errorf("Expected default settings to be IdentityIdsecAuthMethodSettings")
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
