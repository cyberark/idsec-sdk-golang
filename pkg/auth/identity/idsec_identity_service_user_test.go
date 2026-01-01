package identity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// --- Mock Utilities ---

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

// createMockIdentityServer creates a mock HTTP server for testing identity endpoints
func createMockIdentityServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := handlers[r.URL.Path]; ok {
			handler(w, r)
			return
		}
		// Default handler for unmocked paths
		if strings.HasPrefix(r.URL.Path, "/OAuth2/Token/") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token": "mock_access_token"}`))
			return
		}
		http.NotFound(w, r)
	}))
}

// --- Test Helper Functions ---

func CreateTestLogger() *common.IdsecLogger {
	return common.NewIdsecLogger("test", common.Info, false, false)
}

func CreateTestProfile(profileName string) *models.IdsecProfile {
	return &models.IdsecProfile{
		ProfileName: profileName,
	}
}

func CreateTestToken(token string, expiresIn time.Time) *auth.IdsecToken {
	return &auth.IdsecToken{
		Token:     token,
		ExpiresIn: commonmodels.IdsecRFC3339Time(expiresIn),
		Username:  "testuser",
	}
}

// --- Tests ---

func TestNewIdsecIdentityServiceUser(t *testing.T) {
	tests := []struct {
		name                    string
		username                string
		token                   string
		appName                 string
		identityURL             string
		identityTenantSubdomain string
		cacheAuthentication     bool
		loadCache               bool
		cacheProfile            *models.IdsecProfile
		expectedError           bool
		expectedErrorMsg        string
		validateFunc            func(t *testing.T, result *IdsecIdentityServiceUser)
	}{
		// Username Validation Tests (Fix validation)
		{
			name:             "error_username_without_at_symbol",
			username:         "client-id-12345",
			identityURL:      "",
			expectedError:    true,
			expectedErrorMsg: "username must be in email format",
		},
		{
			name:             "error_empty_username",
			username:         "",
			identityURL:      "",
			expectedError:    true,
			expectedErrorMsg: "username must be in email format",
		},
		{
			name:        "success_at_symbol_at_start",
			username:    "@domain.com",
			identityURL: "",
			// This will fail later in FQDN resolution because of network call, but should pass validation
			// We expect an error, but NOT the "username must be in email format" error
			expectedError: true,
		},

		// URL Bypass Tests
		{
			name:        "success_with_identity_url_no_at_required",
			username:    "client-id",
			identityURL: "https://tenant.cyberark.cloud",
			validateFunc: func(t *testing.T, result *IdsecIdentityServiceUser) {
				if result.identityURL != "https://tenant.cyberark.cloud" {
					t.Errorf("Expected identityURL 'https://tenant.cyberark.cloud', got '%s'", result.identityURL)
				}
			},
		},
		{
			name:        "success_with_identity_url_empty_username",
			username:    "",
			identityURL: "https://tenant.cyberark.cloud",
			validateFunc: func(t *testing.T, result *IdsecIdentityServiceUser) {
				if result.username != "" {
					t.Errorf("Expected empty username, got '%s'", result.username)
				}
			},
		},
		{
			name:                    "success_with_tenant_subdomain_no_at_required",
			username:                "client-id",
			identityTenantSubdomain: "mytenant",
			// FQDN resolution might fail due to network call, but validation should pass
			// We check if it bypassed the "username format" check
			expectedError: true, // Error expected from FQDN resolution
		},

		// Initialization Tests
		{
			name:                "success_cache_enabled",
			username:            "user@domain.com",
			identityURL:         "https://tenant.cyberark.cloud",
			cacheAuthentication: true,
			validateFunc: func(t *testing.T, result *IdsecIdentityServiceUser) {
				if result.keyring == nil {
					t.Error("Expected keyring to be initialized when cacheAuthentication is true")
				}
				if result.cacheAuthentication != true {
					t.Error("Expected cacheAuthentication to be true")
				}
			},
		},
		{
			name:                "success_cache_disabled",
			username:            "user@domain.com",
			identityURL:         "https://tenant.cyberark.cloud",
			cacheAuthentication: false,
			validateFunc: func(t *testing.T, result *IdsecIdentityServiceUser) {
				if result.keyring != nil {
					t.Error("Expected keyring to be nil when cacheAuthentication is false")
				}
			},
		},
		{
			name:        "success_session_initialized",
			username:    "user@domain.com",
			identityURL: "https://tenant.cyberark.cloud",
			validateFunc: func(t *testing.T, result *IdsecIdentityServiceUser) {
				if result.session == nil {
					t.Error("Expected session to be initialized")
				}
				if result.session.BaseURL != "https://tenant.cyberark.cloud" {
					t.Errorf("Expected session BaseURL to be 'https://tenant.cyberark.cloud', got '%s'", result.session.BaseURL)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := CreateTestLogger()

			result, err := NewIdsecIdentityServiceUser(
				tt.username,
				tt.token,
				tt.appName,
				tt.identityURL,
				tt.identityTenantSubdomain,
				logger,
				tt.cacheAuthentication,
				tt.loadCache,
				tt.cacheProfile,
			)

			if tt.expectedError {
				if err == nil {
					// For FQDN resolution failures (network calls), we might expect an error
					// but not the validation error
					if tt.expectedErrorMsg == "" && (tt.username == "@domain.com" || tt.identityTenantSubdomain != "") {
						// Expected network error, got validation error? or nil?
						// If nil, it means FQDN resolution somehow succeeded (unexpected in unit test env)
						// If error, we check if it's NOT the validation error
						return
					}
					t.Fatal("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" {
					if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
						t.Errorf("Expected error containing '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				} else if tt.username == "@domain.com" || tt.identityTenantSubdomain != "" {
					// Ensure we didn't get the validation error
					if strings.Contains(err.Error(), "username must be in email format") {
						t.Errorf("Got validation error unexpectedly: %v", err)
					}
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

func TestIdsecIdentityServiceUser_LoadCache(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name           string
		setupMock      func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser
		profile        *models.IdsecProfile
		expectedResult bool
		validateFunc   func(t *testing.T, serviceUser *IdsecIdentityServiceUser)
	}{
		{
			name: "success_load_valid_cached_token",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return &auth.IdsecToken{
						Token:     "cached_token",
						ExpiresIn: commonmodels.IdsecRFC3339Time(futureTime),
						Username:  "testuser",
					}, nil
				}
				logger := CreateTestLogger()
				return &IdsecIdentityServiceUser{
					username: "testuser",
					keyring:  mockKeyring,
					logger:   logger,
					session:  common.NewSimpleIdsecClient("https://test.com"),
				}
			},
			profile:        CreateTestProfile("test"),
			expectedResult: true,
			validateFunc: func(t *testing.T, serviceUser *IdsecIdentityServiceUser) {
				if serviceUser.sessionToken != "cached_token" {
					t.Errorf("Expected sessionToken 'cached_token', got '%s'", serviceUser.sessionToken)
				}
				if !serviceUser.loadedFromCache {
					t.Error("Expected loadedFromCache to be true")
				}
			},
		},
		{
			name: "success_keyring_nil_returns_false",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				return &IdsecIdentityServiceUser{
					username: "testuser",
					keyring:  nil,
					logger:   CreateTestLogger(),
				}
			},
			profile:        CreateTestProfile("test"),
			expectedResult: false,
		},
		{
			name: "success_profile_nil_returns_false",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				return &IdsecIdentityServiceUser{
					username: "testuser",
					keyring:  mockKeyring,
					logger:   CreateTestLogger(),
				}
			},
			profile:        nil,
			expectedResult: false,
		},
		{
			name: "failure_keyring_load_error_returns_false",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return nil, errors.New("keyring error")
				}
				return &IdsecIdentityServiceUser{
					username: "testuser",
					keyring:  mockKeyring,
					logger:   CreateTestLogger(),
				}
			},
			profile:        CreateTestProfile("test"),
			expectedResult: false,
		},
		{
			name: "success_username_mismatch_returns_false",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				mockKeyring.LoadTokenFunc = func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
					return &auth.IdsecToken{
						Token:    "cached_token",
						Username: "otheruser",
					}, nil
				}
				return &IdsecIdentityServiceUser{
					username: "testuser",
					keyring:  mockKeyring,
					logger:   CreateTestLogger(),
				}
			},
			profile:        CreateTestProfile("test"),
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyring := &MockKeyring{}
			serviceUser := tt.setupMock(mockKeyring)

			result := serviceUser.loadCache(tt.profile)

			if result != tt.expectedResult {
				t.Errorf("Expected result %v, got %v", tt.expectedResult, result)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, serviceUser)
			}
		})
	}
}

func TestIdsecIdentityServiceUser_SaveCache(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser
		profile       *models.IdsecProfile
		expectedError bool
	}{
		{
			name: "success_save_token_to_cache",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					if token.Token != "session_token" {
						return errors.New("wrong token saved")
					}
					if token.Username != "testuser" {
						return errors.New("wrong username saved")
					}
					return nil
				}
				return &IdsecIdentityServiceUser{
					username:     "testuser",
					sessionToken: "session_token",
					keyring:      mockKeyring,
					session:      common.NewSimpleIdsecClient("https://test.com"),
					logger:       CreateTestLogger(),
				}
			},
			profile:       CreateTestProfile("test"),
			expectedError: false,
		},
		{
			name: "success_keyring_nil_returns_nil",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				return &IdsecIdentityServiceUser{
					keyring: nil,
				}
			},
			profile:       CreateTestProfile("test"),
			expectedError: false,
		},
		{
			name: "success_profile_nil_returns_nil",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				return &IdsecIdentityServiceUser{
					keyring: mockKeyring,
				}
			},
			profile:       nil,
			expectedError: false,
		},
		{
			name: "success_empty_session_token_returns_nil",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				return &IdsecIdentityServiceUser{
					keyring:      mockKeyring,
					sessionToken: "",
				}
			},
			profile:       CreateTestProfile("test"),
			expectedError: false,
		},
		{
			name: "error_keyring_save_fails",
			setupMock: func(mockKeyring *MockKeyring) *IdsecIdentityServiceUser {
				mockKeyring.SaveTokenFunc = func(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, override bool) error {
					return errors.New("save error")
				}
				return &IdsecIdentityServiceUser{
					username:     "testuser",
					sessionToken: "session_token",
					keyring:      mockKeyring,
					session:      common.NewSimpleIdsecClient("https://test.com"),
					logger:       CreateTestLogger(),
				}
			},
			profile:       CreateTestProfile("test"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKeyring := &MockKeyring{}
			serviceUser := tt.setupMock(mockKeyring)

			err := serviceUser.saveCache(tt.profile)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestIdsecIdentityServiceUser_Getters(t *testing.T) {
	serviceUser := &IdsecIdentityServiceUser{
		username:     "testuser",
		sessionToken: "test_token",
		session:      common.NewSimpleIdsecClient("https://test.com"),
	}

	if serviceUser.Session() == nil {
		t.Error("Session() returned nil")
	}

	if serviceUser.SessionToken() != "test_token" {
		t.Errorf("SessionToken() returned '%s', expected 'test_token'", serviceUser.SessionToken())
	}

	if serviceUser.IdentityURL() != "https://test.com" {
		t.Errorf("IdentityURL() returned '%s', expected 'https://test.com'", serviceUser.IdentityURL())
	}
}
