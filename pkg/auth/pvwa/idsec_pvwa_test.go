package pvwa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestNewIdsecPVWA(t *testing.T) {
	logger := common.NewIdsecLogger("test", common.Critical, false, false)

	tests := []struct {
		name                string
		username            string
		password            string
		pvwaURL             string
		loginMethod         string
		logger              *common.IdsecLogger
		cacheAuthentication bool
		loadCache           bool
		cacheProfile        *models.IdsecProfile
		expectedError       bool
		expectedErrorMsg    string
		validateFunc        func(t *testing.T, result *IdsecPVWA)
	}{
		{
			name:                "error_empty_pvwa_url",
			username:            "user",
			password:            "pass",
			pvwaURL:             "",
			loginMethod:         auth.PVWALoginMethodCyberArk,
			logger:              logger,
			cacheAuthentication: false,
			loadCache:           false,
			cacheProfile:        nil,
			expectedError:       true,
			expectedErrorMsg:    "pvwa URL is required",
		},
		{
			name:                "error_empty_login_method",
			username:            "user",
			password:            "pass",
			pvwaURL:             "https://pvwa.example.com",
			loginMethod:         "",
			logger:              logger,
			cacheAuthentication: false,
			loadCache:           false,
			cacheProfile:        nil,
			expectedError:       true,
			expectedErrorMsg:    "login method is required",
		},
		{
			name:                "success_minimal_params_no_cache",
			username:            "admin",
			password:            "secret",
			pvwaURL:             "https://pvwa.example.com",
			loginMethod:         auth.PVWALoginMethodCyberArk,
			logger:              logger,
			cacheAuthentication: false,
			loadCache:           false,
			cacheProfile:        nil,
			expectedError:       false,
			validateFunc: func(t *testing.T, result *IdsecPVWA) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecPVWA")
				}
				if result.PVWAURL() != "https://pvwa.example.com" {
					t.Errorf("Expected PVWAURL 'https://pvwa.example.com', got '%s'", result.PVWAURL())
				}
				if result.Session() == nil {
					t.Error("Expected non-nil Session")
				}
				if result.SessionToken() != "" {
					t.Errorf("Expected empty SessionToken before Auth, got '%s'", result.SessionToken())
				}
			},
		},
		{
			name:                "success_with_different_login_method",
			username:            "user",
			password:            "pwd",
			pvwaURL:             "https://vault.example.com",
			loginMethod:         auth.PVWALoginMethodLDAP,
			logger:              logger,
			cacheAuthentication: false,
			loadCache:           false,
			cacheProfile:        nil,
			expectedError:       false,
			validateFunc: func(t *testing.T, result *IdsecPVWA) {
				if result == nil {
					t.Fatal("Expected non-nil IdsecPVWA")
				}
				if result.PVWAURL() != "https://vault.example.com" {
					t.Errorf("Expected PVWAURL 'https://vault.example.com', got '%s'", result.PVWAURL())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := NewIdsecPVWA(tt.username, tt.password, tt.pvwaURL, tt.loginMethod, tt.logger, tt.cacheAuthentication, tt.loadCache, tt.cacheProfile)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecPVWA_Session(t *testing.T) {
	logger := common.NewIdsecLogger("test", common.Critical, false, false)

	t.Run("success_returns_non_nil_session", func(t *testing.T) {
		t.Parallel()

		p, err := NewIdsecPVWA("u", "p", "https://pvwa.example.com", auth.PVWALoginMethodCyberArk, logger, false, false, nil)
		if err != nil {
			t.Fatalf("NewIdsecPVWA: %v", err)
		}
		if p.Session() == nil {
			t.Error("Expected non-nil Session")
		}
	})
}

func TestIdsecPVWA_SessionToken(t *testing.T) {
	logger := common.NewIdsecLogger("test", common.Critical, false, false)

	t.Run("success_empty_before_auth", func(t *testing.T) {
		t.Parallel()

		p, err := NewIdsecPVWA("u", "p", "https://pvwa.example.com", auth.PVWALoginMethodCyberArk, logger, false, false, nil)
		if err != nil {
			t.Fatalf("NewIdsecPVWA: %v", err)
		}
		if p.SessionToken() != "" {
			t.Errorf("Expected empty SessionToken before Auth, got '%s'", p.SessionToken())
		}
	})
}

func TestIdsecPVWA_PVWAURL(t *testing.T) {
	logger := common.NewIdsecLogger("test", common.Critical, false, false)

	tests := []struct {
		name        string
		pvwaURL     string
		expectedURL string
	}{
		{
			name:        "success_returns_provided_url",
			pvwaURL:     "https://custom.example.com",
			expectedURL: "https://custom.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := NewIdsecPVWA("u", "p", tt.pvwaURL, auth.PVWALoginMethodCyberArk, logger, false, false, nil)
			if err != nil {
				t.Fatalf("NewIdsecPVWA: %v", err)
			}
			if p.PVWAURL() != tt.expectedURL {
				t.Errorf("Expected PVWAURL '%s', got '%s'", tt.expectedURL, p.PVWAURL())
			}
		})
	}
}

func TestDefaultTokenLifetimeSeconds(t *testing.T) {
	t.Run("success_constant_is_3600", func(t *testing.T) {
		t.Parallel()
		if authcommon.DefaultTokenLifetimeSeconds != 3600 {
			t.Errorf("Expected DefaultTokenLifetimeSeconds 3600, got %d", authcommon.DefaultTokenLifetimeSeconds)
		}
	})
}

func TestGetCacheKey(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		expectedKey string
	}{
		{
			name:        "success_simple_username",
			username:    "admin",
			expectedKey: "admin_pvwa",
		},
		{
			name:        "success_username_with_underscore",
			username:    "admin_user",
			expectedKey: "admin_user_pvwa",
		},
		{
			name:        "success_empty_username",
			username:    "",
			expectedKey: "_pvwa",
		},
		{
			name:        "success_username_with_numbers",
			username:    "user123",
			expectedKey: "user123_pvwa",
		},
		{
			name:        "success_username_with_special_chars",
			username:    "user@domain.com",
			expectedKey: "user@domain.com_pvwa",
		},
		{
			name:        "success_username_with_spaces",
			username:    "admin user",
			expectedKey: "admin user_pvwa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := getCacheKey(tt.username)
			if result != tt.expectedKey {
				t.Errorf("Expected cache key '%s', got '%s'", tt.expectedKey, result)
			}
		})
	}
}

func TestAuthPVWA(t *testing.T) {
	logger := common.NewIdsecLogger("test", common.Critical, false, false)
	logonPath := "/PasswordVault/API/auth/cyberark/Logon/"

	tests := []struct {
		name          string
		handler       func(w http.ResponseWriter, r *http.Request)
		expectedError bool
		errorContains string
		validateFunc  func(t *testing.T, p *IdsecPVWA)
	}{
		{
			name: "success_200_with_valid_token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != logonPath || r.Method != http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode("secret-token-123")
			},
			expectedError: false,
			validateFunc: func(t *testing.T, p *IdsecPVWA) {
				if p.SessionToken() != "secret-token-123" {
					t.Errorf("Expected SessionToken 'secret-token-123', got '%s'", p.SessionToken())
				}
			},
		},
		{
			name: "error_200_with_empty_token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != logonPath || r.Method != http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode("")
			},
			expectedError: true,
			errorContains: "invalid token response",
		},
		{
			name: "error_non_200_with_api_error_json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != logonPath || r.Method != http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ErrorCode":"LOGON_FAILED","ErrorMessage":"Invalid credentials"}`))
			},
			expectedError: true,
			errorContains: "LOGON_FAILED",
		},
		{
			name: "error_non_200_with_invalid_json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != logonPath || r.Method != http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("not valid json"))
			},
			expectedError: true,
			errorContains: "failed to decode PVWA Auth API error response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(tt.handler))
			defer server.Close()

			config.DisableCertificateVerification()
			defer config.EnableCertificateVerification()

			p, err := NewIdsecPVWA("admin", "pass", server.URL, auth.PVWALoginMethodCyberArk, logger, false, false, nil)
			if err != nil {
				t.Fatalf("NewIdsecPVWA: %v", err)
			}

			err = p.AuthPVWA(nil, false)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, p)
			}
		})
	}
}
