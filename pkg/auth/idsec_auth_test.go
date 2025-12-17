package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// CreateTestProfile creates a test profile with auth profiles
func CreateTestProfile(profileName string, authProfileName string, username string) *models.IdsecProfile {
	profile := &models.IdsecProfile{
		ProfileName: profileName,
		AuthProfiles: map[string]*auth.IdsecAuthProfile{
			authProfileName: {
				Username:   username,
				AuthMethod: auth.Direct,
				AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
					Endpoint: "https://test.example.com",
				},
			},
		},
	}
	return profile
}

// CreateTestToken creates a test token
func CreateTestToken(accessToken string, expiresIn time.Time, refreshToken string) *auth.IdsecToken {
	return &auth.IdsecToken{
		Token:        accessToken,
		ExpiresIn:    common.IdsecRFC3339Time(expiresIn),
		RefreshToken: refreshToken,
	}
}

// CreateTestAuthProfile creates a test auth profile
func CreateTestAuthProfile(username string, authMethod auth.IdsecAuthMethod, endpoint string) *auth.IdsecAuthProfile {
	return &auth.IdsecAuthProfile{
		Username:   username,
		AuthMethod: authMethod,
		AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
			Endpoint: endpoint,
		},
	}
}

// MockIdsecAuth is a mock implementation of the IdsecAuth interface
type MockIdsecAuth struct {
	AuthenticatorNameFunc              func() string
	AuthenticatorHumanReadableNameFunc func() string
	SupportedAuthMethodsFunc           func() []auth.IdsecAuthMethod
	IsAuthenticatedFunc                func(profile *models.IdsecProfile) bool
	DefaultAuthMethodFunc              func() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings)
	LoadAuthenticationFunc             func(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error)
	AuthenticateFunc                   func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error)
	PerformAuthenticationFunc          func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error)
	PerformRefreshAuthenticationFunc   func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error)
}

func (m *MockIdsecAuth) AuthenticatorName() string {
	if m.AuthenticatorNameFunc != nil {
		return m.AuthenticatorNameFunc()
	}
	return "mock_auth"
}

func (m *MockIdsecAuth) AuthenticatorHumanReadableName() string {
	if m.AuthenticatorHumanReadableNameFunc != nil {
		return m.AuthenticatorHumanReadableNameFunc()
	}
	return "Mock Auth"
}

func (m *MockIdsecAuth) SupportedAuthMethods() []auth.IdsecAuthMethod {
	if m.SupportedAuthMethodsFunc != nil {
		return m.SupportedAuthMethodsFunc()
	}
	return []auth.IdsecAuthMethod{auth.Direct}
}

func (m *MockIdsecAuth) IsAuthenticated(profile *models.IdsecProfile) bool {
	if m.IsAuthenticatedFunc != nil {
		return m.IsAuthenticatedFunc(profile)
	}
	return false
}

func (m *MockIdsecAuth) DefaultAuthMethod() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings) {
	if m.DefaultAuthMethodFunc != nil {
		return m.DefaultAuthMethodFunc()
	}
	return auth.Direct, auth.DirectIdsecAuthMethodSettings{Endpoint: "https://default.example.com"}
}

func (m *MockIdsecAuth) LoadAuthentication(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error) {
	if m.LoadAuthenticationFunc != nil {
		return m.LoadAuthenticationFunc(profile, refreshAuth)
	}
	return nil, nil
}

func (m *MockIdsecAuth) Authenticate(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(profile, authProfile, secret, force, refreshAuth)
	}
	return nil, nil
}

// Unexported methods required by the interface
func (m *MockIdsecAuth) performAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	if m.PerformAuthenticationFunc != nil {
		return m.PerformAuthenticationFunc(profile, authProfile, secret, force)
	}
	return nil, errors.New("not implemented")
}

func (m *MockIdsecAuth) performRefreshAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
	if m.PerformRefreshAuthenticationFunc != nil {
		return m.PerformRefreshAuthenticationFunc(profile, authProfile, token)
	}
	return nil, errors.New("not implemented")
}

// MockKeyring is a mock implementation of keyring operations
type MockKeyring struct {
	LoadTokenFunc func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error)
	SaveTokenFunc func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error
}

func (m *MockKeyring) LoadToken(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
	if m.LoadTokenFunc != nil {
		return m.LoadTokenFunc(profile, postfix, override)
	}
	return nil, nil
}

func (m *MockKeyring) SaveToken(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
	if m.SaveTokenFunc != nil {
		return m.SaveTokenFunc(profile, token, postfix, override)
	}
	return nil
}

func TestNewIdsecAuthBase(t *testing.T) {
	tests := []struct {
		name                string
		cacheAuthentication bool
		authenticatorName   string
		validateFunc        func(t *testing.T, result *IdsecAuthBase)
	}{
		{
			name:                "success_with_caching_enabled",
			cacheAuthentication: true,
			authenticatorName:   "test_auth",
			validateFunc: func(t *testing.T, result *IdsecAuthBase) {
				if !result.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be true, got false")
				}
				if result.CacheKeyring == nil {
					t.Errorf("Expected CacheKeyring to be initialized when caching is enabled")
				}
			},
		},
		{
			name:                "success_with_caching_disabled",
			cacheAuthentication: false,
			authenticatorName:   "test_auth_no_cache",
			validateFunc: func(t *testing.T, result *IdsecAuthBase) {
				if result.CacheAuthentication {
					t.Errorf("Expected CacheAuthentication to be false, got true")
				}
				if result.CacheKeyring != nil {
					t.Errorf("Expected CacheKeyring to be nil when caching is disabled")
				}
			},
		},
		{
			name:                "success_logger_initialized",
			cacheAuthentication: true,
			authenticatorName:   "test_logger",
			validateFunc: func(t *testing.T, result *IdsecAuthBase) {
				if result.Logger == nil {
					t.Errorf("Expected Logger to be initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &MockIdsecAuth{}
			result := NewIdsecAuthBase(tt.cacheAuthentication, tt.authenticatorName, mockAuth)

			if result == nil {
				t.Fatal("Expected non-nil IdsecAuthBase")
			}

			if result.Authenticator.AuthenticatorName() != mockAuth.AuthenticatorName() {
				t.Errorf("Expected Authenticator to be set to the provided mock")
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestResolveCachePostfix(t *testing.T) {
	tests := []struct {
		name           string
		authProfile    *auth.IdsecAuthProfile
		expectedResult string
	}{
		{
			name: "success_direct_auth_with_endpoint_extracts_host",
			authProfile: &auth.IdsecAuthProfile{
				Username:   "testuser",
				AuthMethod: auth.Direct,
				AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
					Endpoint: "https://test.example.com/api/v1",
				},
			},
			expectedResult: "testuser_test.example.com",
		},
		{
			name: "success_direct_auth_without_endpoint_returns_username",
			authProfile: &auth.IdsecAuthProfile{
				Username:           "testuser2",
				AuthMethod:         auth.Direct,
				AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{},
			},
			expectedResult: "testuser2",
		},
		{
			name: "success_non_direct_auth_returns_username_only",
			authProfile: &auth.IdsecAuthProfile{
				Username:   "testuser3",
				AuthMethod: auth.Identity,
			},
			expectedResult: "testuser3",
		},
		{
			name: "success_empty_username_with_endpoint",
			authProfile: &auth.IdsecAuthProfile{
				Username:   "",
				AuthMethod: auth.Direct,
				AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
					Endpoint: "https://example.com",
				},
			},
			expectedResult: "_example.com",
		},
		{
			name: "success_endpoint_with_port",
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user",
				AuthMethod: auth.Direct,
				AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
					Endpoint: "https://test.example.com:8080/path",
				},
			},
			expectedResult: "user_test.example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &MockIdsecAuth{}
			base := NewIdsecAuthBase(false, "test", mockAuth)

			result := base.ResolveCachePostfix(tt.authProfile)

			if result != tt.expectedResult {
				t.Errorf("Expected postfix '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	pastTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name             string
		profile          *models.IdsecProfile
		authProfile      *auth.IdsecAuthProfile
		secret           *auth.IdsecSecret
		force            bool
		refreshAuth      bool
		setupMock        func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase)
	}{
		{
			name:        "error_both_profile_and_auth_profile_nil",
			profile:     nil,
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError:    true,
			expectedErrorMsg: "either a profile or a specific auth profile must be supplied",
		},
		{
			name:        "error_auth_profile_not_found_in_profile",
			profile:     CreateTestProfile("test", "different_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.AuthenticatorHumanReadableNameFunc = func() string { return "Mock Auth" }
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError:    true,
			expectedErrorMsg: "Mock Auth [mock_auth] is not defined within the authentication profiles",
		},
		{
			name:    "error_unsupported_auth_method",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.Identity,
			},
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.AuthenticatorHumanReadableNameFunc = func() string { return "Mock Auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError:    true,
			expectedErrorMsg: "Mock Auth does not support authentication method identity",
		},
		{
			name:    "error_missing_username_for_credential_method",
			profile: CreateTestProfile("test", "mock_auth", ""),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "",
				AuthMethod: auth.Direct,
			},
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.AuthenticatorHumanReadableNameFunc = func() string { return "Mock Auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError:    true,
			expectedErrorMsg: "Mock Auth requires a username and optionally a secret",
		},
		{
			name:        "success_perform_new_authentication",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      &auth.IdsecSecret{Secret: "password"},
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					return CreateTestToken("new_access_token", futureTime, "refresh_token"), nil
				}
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "new_access_token" {
					t.Errorf("Expected token 'new_access_token', got '%s'", result.Token)
				}
				if base.Token != result {
					t.Errorf("Expected base.Token to be set")
				}
				if base.ActiveProfile == nil {
					t.Errorf("Expected ActiveProfile to be set")
				}
				if base.ActiveAuthProfile == nil {
					t.Errorf("Expected ActiveAuthProfile to be set")
				}
			},
		},
		{
			name:        "success_load_valid_cached_token",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("cached_token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "cached_token" {
					t.Errorf("Expected cached token, got '%s'", result.Token)
				}
			},
		},
		{
			name:        "success_expired_cached_token_with_refresh",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: true,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("expired_token", pastTime, "refresh_token"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return nil
				}
				mockAuth.PerformRefreshAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
					if token.Token == "expired_token" {
						return CreateTestToken("refreshed_token", futureTime, "new_refresh"), nil
					}
					return nil, errors.New("unexpected token")
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "refreshed_token" {
					t.Errorf("Expected refreshed token, got '%s'", result.Token)
				}
			},
		},
		{
			name:        "success_force_bypasses_cache",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       true,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					if force {
						return CreateTestToken("forced_new_token", futureTime, "refresh"), nil
					}
					return nil, errors.New("force flag not passed")
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "forced_new_token" {
					t.Errorf("Expected forced new token, got '%s'", result.Token)
				}
			},
		},
		{
			name:    "success_default_auth_method_resolved",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: &auth.IdsecAuthProfile{
				Username:   "user1",
				AuthMethod: auth.Default,
			},
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.DefaultAuthMethodFunc = func() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings) {
					return auth.Direct, auth.DirectIdsecAuthMethodSettings{Endpoint: "https://default.example.com"}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					if authProfile.AuthMethod == auth.Direct {
						return CreateTestToken("token", futureTime, "refresh"), nil
					}
					return nil, errors.New("auth method not resolved")
				}
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
			},
		},
		{
			name:        "success_token_saved_to_cache_after_auth",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					return CreateTestToken("new_token", futureTime, "refresh"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return nil
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
			},
		},
		{
			name:        "error_perform_authentication_fails",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      &auth.IdsecSecret{Secret: "password"},
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					return nil, errors.New("authentication failed")
				}
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedError:    true,
			expectedErrorMsg: "authentication failed",
		},
		{
			name:        "error_cache_load_fails",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return nil, errors.New("cache load failed")
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError:    true,
			expectedErrorMsg: "cache load failed",
		},
		{
			name:        "error_cache_save_fails_after_auth",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					return CreateTestToken("new_token", futureTime, "refresh"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return errors.New("cache save failed")
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError:    true,
			expectedErrorMsg: "cache save failed",
		},
		{
			name:        "error_cache_save_fails_after_refresh",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       false,
			refreshAuth: true,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("valid_token", futureTime, "refresh"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					// Fail on save when token is refreshed
					if token.Token == "refreshed_token" {
						return errors.New("cache save failed after refresh")
					}
					return nil
				}
				mockAuth.PerformRefreshAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
					return CreateTestToken("refreshed_token", futureTime.Add(1*time.Hour), "new_refresh"), nil
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError:    true,
			expectedErrorMsg: "cache save failed after refresh",
		},
		{
			name:        "success_force_with_cached_token_skips_cache",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			authProfile: nil,
			secret:      nil,
			force:       true,
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockAuth.SupportedAuthMethodsFunc = func() []auth.IdsecAuthMethod {
					return []auth.IdsecAuthMethod{auth.Direct}
				}
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("cached_token", futureTime, "refresh"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return nil
				}
				mockAuth.PerformAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
					if !force {
						return nil, errors.New("force should be true")
					}
					return CreateTestToken("forced_token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "forced_token" {
					t.Errorf("Expected forced token, got '%s'", result.Token)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &MockIdsecAuth{}
			mockKeyring := &MockKeyring{}
			base := tt.setupMock(mockAuth, mockKeyring)

			result, err := base.Authenticate(tt.profile, tt.authProfile, tt.secret, tt.force, tt.refreshAuth)

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
				tt.validateFunc(t, result, base)
			}
		})
	}
}

func TestIsAuthenticated(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	pastTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name           string
		profile        *models.IdsecProfile
		setupMock      func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase
		expectedResult bool
	}{
		{
			name:    "success_token_already_loaded_in_memory",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.Token = CreateTestToken("loaded_token", futureTime, "refresh")
				return base
			},
			expectedResult: true,
		},
		{
			name:    "success_valid_token_loaded_from_cache",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("cached_token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedResult: true,
		},
		{
			name:    "failure_expired_cached_token",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("expired_token", pastTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedResult: false,
		},
		{
			name:    "failure_no_matching_auth_profile",
			profile: CreateTestProfile("test", "different_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				return NewIdsecAuthBase(false, "test", mockAuth)
			},
			expectedResult: false,
		},
		{
			name:    "failure_keyring_load_error",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return nil, errors.New("keyring error")
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedResult: false,
		},
		{
			name:    "failure_no_keyring_and_no_loaded_token",
			profile: CreateTestProfile("test", "mock_auth", "user1"),
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = nil
				return base
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &MockIdsecAuth{}
			mockKeyring := &MockKeyring{}
			base := tt.setupMock(mockAuth, mockKeyring)

			result := base.IsAuthenticated(tt.profile)

			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestLoadAuthentication(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	pastTime := time.Now().Add(-1 * time.Hour)
	nearExpiryTime := time.Now().Add(30 * time.Second) // Within grace period

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		refreshAuth   bool
		setupMock     func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase
		expectedError bool
		validateFunc  func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase)
	}{
		{
			name:        "success_load_valid_token_from_cache",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("cached_token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "cached_token" {
					t.Errorf("Expected 'cached_token', got '%s'", result.Token)
				}
			},
		},
		{
			name:        "success_refresh_token_near_expiry",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: true,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("near_expiry_token", nearExpiryTime, "refresh_token"), nil
				}
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return nil
				}
				mockAuth.PerformRefreshAuthenticationFunc = func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
					return CreateTestToken("refreshed_token", futureTime, "new_refresh"), nil
				}
				base := NewIdsecAuthBase(true, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "refreshed_token" {
					t.Errorf("Expected refreshed token, got '%s'", result.Token)
				}
			},
		},
		{
			name:        "success_no_refresh_for_valid_token_beyond_grace",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: true,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("valid_token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result == nil {
					t.Fatal("Expected non-nil token")
				}
				if result.Token != "valid_token" {
					t.Errorf("Expected original valid token without refresh")
				}
			},
		},
		{
			name:        "success_expired_token_returns_nil",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("expired_token", pastTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result != nil {
					t.Errorf("Expected nil token for expired authentication")
				}
			},
		},
		{
			name:        "success_no_auth_profile_returns_nil",
			profile:     CreateTestProfile("test", "different_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				base := NewIdsecAuthBase(false, "test", mockAuth)
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if result != nil {
					t.Errorf("Expected nil token when no auth profile exists")
				}
			},
		},
		{
			name:        "error_keyring_load_failure",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return nil, errors.New("keyring access denied")
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: true,
		},
		{
			name:        "success_sets_active_profile_and_auth_profile",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if base.ActiveProfile == nil {
					t.Errorf("Expected ActiveProfile to be set")
				}
				if base.ActiveAuthProfile == nil {
					t.Errorf("Expected ActiveAuthProfile to be set")
				}
			},
		},
		{
			name:        "error_keyring_load_failure",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return nil, errors.New("keyring access denied")
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				return base
			},
			expectedError: true,
		},
		{
			name:        "success_sets_active_profile_and_auth_profile",
			profile:     CreateTestProfile("test", "mock_auth", "user1"),
			refreshAuth: false,
			setupMock: func(mockAuth *MockIdsecAuth, mockKeyring *MockKeyring) *IdsecAuthBase {
				mockAuth.AuthenticatorNameFunc = func() string { return "mock_auth" }
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return CreateTestToken("token", futureTime, "refresh"), nil
				}
				base := NewIdsecAuthBase(false, "test", mockAuth)
				base.CacheKeyring = mockKeyring
				base.ActiveAuthProfile = &auth.IdsecAuthProfile{
					Username:   "user1",
					AuthMethod: auth.Direct,
				}
				return base
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *auth.IdsecToken, base *IdsecAuthBase) {
				if base.ActiveProfile == nil {
					t.Errorf("Expected ActiveProfile to be set")
				}
				if base.ActiveAuthProfile == nil {
					t.Errorf("Expected ActiveAuthProfile to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &MockIdsecAuth{}
			mockKeyring := &MockKeyring{}
			base := tt.setupMock(mockAuth, mockKeyring)

			result, err := base.LoadAuthentication(tt.profile, tt.refreshAuth)

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
				tt.validateFunc(t, result, base)
			}
		})
	}
}
