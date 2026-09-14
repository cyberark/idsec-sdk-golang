package auth

import (
	"errors"
	"testing"
	"time"

	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// TestLoadCachedToken verifies that LoadCachedToken returns raw cached tokens
// (including expired ones), unlike IsAuthenticated which treats an expired
// cached token as absent. This is what lets a status probe tell
// "token-expired" apart from "never authenticated".
func TestLoadCachedToken(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	futureTime := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		setup         func(authInstance *IdsecISPAuth)
		expectToken   bool
		expectExpired bool
		expectKeyring bool
	}{
		{
			name:    "expired_token_is_returned",
			profile: CreateTestProfile("test", "isp", "user1"),
			setup: func(authInstance *IdsecISPAuth) {
				authInstance.CacheKeyring = &MockKeyring{
					LoadTokenFunc: func(_ *models.IdsecProfile, _ string, _ bool) (*auth.IdsecToken, error) {
						return CreateTestToken("expired_token", pastTime, "refresh"), nil
					},
				}
			},
			expectToken:   true,
			expectExpired: true,
		},
		{
			name:    "valid_token_is_returned",
			profile: CreateTestProfile("test", "isp", "user1"),
			setup: func(authInstance *IdsecISPAuth) {
				authInstance.CacheKeyring = &MockKeyring{
					LoadTokenFunc: func(_ *models.IdsecProfile, _ string, _ bool) (*auth.IdsecToken, error) {
						return CreateTestToken("valid_token", futureTime, "refresh"), nil
					},
				}
			},
			expectToken:   true,
			expectExpired: false,
		},
		{
			name:    "no_cached_token_returns_nil",
			profile: CreateTestProfile("test", "isp", "user1"),
			setup: func(authInstance *IdsecISPAuth) {
				authInstance.CacheKeyring = &MockKeyring{
					LoadTokenFunc: func(_ *models.IdsecProfile, _ string, _ bool) (*auth.IdsecToken, error) {
						return nil, nil
					},
				}
			},
			expectToken: false,
		},
		{
			name:    "no_auth_profile_returns_nil",
			profile: CreateTestProfile("test", "different_auth", "user1"),
			setup: func(authInstance *IdsecISPAuth) {
				authInstance.CacheKeyring = &MockKeyring{
					LoadTokenFunc: func(_ *models.IdsecProfile, _ string, _ bool) (*auth.IdsecToken, error) {
						return CreateTestToken("should_not_be_read", futureTime, "refresh"), nil
					},
				}
			},
			expectToken: false,
		},
		{
			name:    "keyring_error_is_classified",
			profile: CreateTestProfile("test", "isp", "user1"),
			setup: func(authInstance *IdsecISPAuth) {
				authInstance.CacheKeyring = &MockKeyring{
					LoadTokenFunc: func(_ *models.IdsecProfile, _ string, _ bool) (*auth.IdsecToken, error) {
						return nil, errors.New("keyring locked")
					},
				}
			},
			expectKeyring: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
			if tt.setup != nil {
				tt.setup(authInstance)
			}

			token, err := authInstance.LoadCachedToken(tt.profile)

			if tt.expectKeyring {
				if err == nil {
					t.Fatalf("expected a keyring error, got nil")
				}
				if reason, ok := authcommon.Classify(err); !ok || reason != authcommon.ReasonKeyringFailure {
					t.Fatalf("keyring error classified as (%q, %v), want (KEYRING_FAILURE, true)", reason, ok)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectToken != (token != nil) {
				t.Fatalf("token presence = %v, want %v", token != nil, tt.expectToken)
			}
			if token != nil {
				expired := time.Time(token.ExpiresIn).Before(time.Now())
				if expired != tt.expectExpired {
					t.Errorf("token expired = %v, want %v", expired, tt.expectExpired)
				}
				if authInstance.IsAuthenticated(tt.profile) && tt.expectExpired {
					t.Errorf("IsAuthenticated returned true for an expired token; LoadCachedToken must not affect it")
				}
			}
		})
	}
}
