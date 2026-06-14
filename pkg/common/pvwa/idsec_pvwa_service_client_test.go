package pvwa

import (
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestNewIdsecPVWAServiceClient(t *testing.T) {
	const (
		endpoint     = "https://pvwa.example.com/"
		sessionToken = "pvwa-session-token"
		serviceName  = "pamsh-pamshaccounts"
	)

	tests := []struct {
		name             string
		endpoint         string
		sessionToken     string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *IdsecPVWAServiceClient)
	}{
		{
			name:          "success_with_nil_cookie_jar",
			endpoint:      endpoint,
			sessionToken:  sessionToken,
			expectedError: false,
			validateFunc: func(t *testing.T, result *IdsecPVWAServiceClient) {
				if result == nil || result.IdsecClient == nil {
					t.Fatal("Expected non-nil client")
				}
				if result.GetToken() != sessionToken {
					t.Errorf("Expected token %q, got %q", sessionToken, result.GetToken())
				}
			},
		},
		{
			name:          "success_happy_path_https_endpoint",
			endpoint:      "  https://pvwa.example.com/  ",
			sessionToken:  sessionToken,
			expectedError: false,
			validateFunc: func(t *testing.T, result *IdsecPVWAServiceClient) {
				if result == nil || result.IdsecClient == nil {
					t.Fatal("Expected non-nil client")
				}
				if result.BaseURL != "https://pvwa.example.com" {
					t.Errorf("Expected BaseURL %q, got %q", "https://pvwa.example.com", result.BaseURL)
				}
				if result.GetToken() != sessionToken {
					t.Errorf("Expected token %q, got %q", sessionToken, result.GetToken())
				}
				if result.GetTokenType() != common.IdsecAuthorizationTokenTypeRaw {
					t.Errorf("Expected token type %q, got %q", common.IdsecAuthorizationTokenTypeRaw, result.GetTokenType())
				}
				headers := result.GetHeaders()
				if headers["Content-Type"] != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %q", headers["Content-Type"])
				}
				if headers["Authorization"] != sessionToken {
					t.Errorf("Expected raw Authorization %q, got %q", sessionToken, headers["Authorization"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := NewIdsecPVWAServiceClient(
				tt.endpoint,
				tt.sessionToken,
				serviceName,
				nil,
			)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.expectedErrorMsg, err.Error())
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

func TestFromPVWAAuth(t *testing.T) {
	const (
		endpoint     = "https://pvwa.example.com"
		sessionToken = "pvwa-session-token"
		serviceName  = "pamsh-pamshsafes"
	)

	tests := []struct {
		name             string
		setupPVWAAuth    func() *auth.IdsecPVWAAuth
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *IdsecPVWAServiceClient)
	}{
		{
			name: "success_with_valid_token",
			setupPVWAAuth: func() *auth.IdsecPVWAAuth {
				return &auth.IdsecPVWAAuth{
					IdsecAuthBase: &auth.IdsecAuthBase{
						Token: &authmodels.IdsecToken{
							Endpoint: endpoint,
							Token:    sessionToken,
						},
					},
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *IdsecPVWAServiceClient) {
				if result == nil || result.IdsecClient == nil {
					t.Fatal("Expected non-nil client")
				}
				if result.BaseURL != endpoint {
					t.Errorf("Expected BaseURL %q, got %q", endpoint, result.BaseURL)
				}
				if result.GetToken() != sessionToken {
					t.Errorf("Expected token %q, got %q", sessionToken, result.GetToken())
				}
			},
		},
		{
			name: "error_nil_auth",
			setupPVWAAuth: func() *auth.IdsecPVWAAuth {
				return nil
			},
			expectedError:    true,
			expectedErrorMsg: "PVWA: missing auth or token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pvwaAuth := tt.setupPVWAAuth()
			result, err := FromPVWAAuth(pvwaAuth, serviceName, nil)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.expectedErrorMsg, err.Error())
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

func TestApplyTokenToClient(t *testing.T) {
	t.Parallel()

	const (
		endpoint     = "https://pvwa.example.com"
		initialToken = "initial-session-token"
		updatedToken = "updated-session-token"
		serviceName  = "pamsh-pamshaccounts"
	)

	client, err := NewIdsecPVWAServiceClient(endpoint, initialToken, serviceName, nil)
	if err != nil {
		t.Fatalf("setup client: %v", err)
	}

	ApplyTokenToClient(client.IdsecClient, updatedToken)
	if client.GetToken() != updatedToken {
		t.Errorf("Expected token %q, got %q", updatedToken, client.GetToken())
	}
}
