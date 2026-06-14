package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// newConcurrencyTestBase builds an IdsecAuthBase wired with a mock authenticator and keyring
// that always return a fresh, valid token. This mirrors the shared-authenticator scenario the
// Terraform provider creates, where one *IdsecISPAuth is used by many goroutines.
func newConcurrencyTestBase() *IdsecAuthBase {
	futureTime := time.Now().Add(1 * time.Hour)

	mockAuth := &MockIdsecAuth{
		AuthenticatorNameFunc: func() string { return "mock_auth" },
		PerformRefreshAuthenticationFunc: func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
			refreshed := CreateTestToken("refreshed_token", time.Now().Add(1*time.Hour), "refresh")
			refreshed.Username = "user1@example.com"
			refreshed.Metadata = map[string]interface{}{"env": "prod"}
			return refreshed, nil
		},
	}
	mockKeyring := &MockKeyring{
		LoadTokenFunc: func(profile *models.IdsecProfile, postfix string, override bool) (*auth.IdsecToken, error) {
			cached := CreateTestToken("cached_token", futureTime, "refresh")
			cached.Username = "user1@example.com"
			cached.Metadata = map[string]interface{}{"env": "prod"}
			return cached, nil
		},
	}

	base := NewIdsecAuthBase(true, "test", mockAuth)
	base.CacheKeyring = mockKeyring
	base.ActiveProfile = CreateTestProfile("test", "mock_auth", "user1")
	base.ActiveAuthProfile = &auth.IdsecAuthProfile{
		Username:   "user1",
		AuthMethod: auth.Direct,
		AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{
			Endpoint: "https://test.example.com",
		},
	}
	initial := CreateTestToken("initial_token", futureTime, "refresh")
	initial.Username = "user1@example.com"
	initial.Metadata = map[string]interface{}{"env": "prod"}
	base.setState(initial, base.ActiveProfile, base.ActiveAuthProfile)
	return base
}

// TestConcurrentTokenAccess exercises the shared authenticator from many goroutines that
// concurrently refresh and read the token. It guards against the nil-pointer crash seen in the
// field (a reader observing a transiently-nil Token mid-refresh) and, under `go test -race`,
// against data races on the auth state. Before the synchronization fix this test panics or
// reports a race; after it, readers always observe a complete, non-nil token.
func TestConcurrentTokenAccess(t *testing.T) {
	base := newConcurrencyTestBase()

	const (
		writers    = 4
		readers    = 16
		iterations = 500
	)

	var wg sync.WaitGroup

	// Writers continuously refresh the shared token.
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if _, err := base.LoadAuthentication(nil, true); err != nil {
					t.Errorf("LoadAuthentication returned error: %v", err)
					return
				}
			}
		}()
	}

	// Readers continuously snapshot and dereference the token, the same way FromISPAuth does.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				token := base.GetToken()
				if token == nil {
					// A nil token here would be the field crash: a reader observing a
					// transiently-nil pointer while a refresh is in progress.
					t.Errorf("GetToken returned nil while a valid token should always be published")
					return
				}
				// Touch the fields FromISPAuth dereferences.
				_ = token.Username
				_ = token.Token
				_ = token.Metadata["env"]
			}
		}()
	}

	wg.Wait()
}

// TestLoadAuthentication_NoKeyringPreservesInMemoryToken guards against the regression where
// LoadAuthentication discarded the valid in-memory token when caching was disabled (no keyring),
// causing it to attempt a doomed refresh and clear the token (leading to 401s). With a valid,
// non-expired in-memory token and no keyring, LoadAuthentication must keep that token.
func TestLoadAuthentication_NoKeyringPreservesInMemoryToken(t *testing.T) {
	refreshCalled := false
	mockAuth := &MockIdsecAuth{
		AuthenticatorNameFunc: func() string { return "mock_auth" },
		PerformRefreshAuthenticationFunc: func(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
			// Simulates the caching-disabled case where there is no session to refresh from.
			refreshCalled = true
			return nil, nil
		},
	}

	// No keyring: caching disabled, exactly like the acceptance/E2E provider configuration.
	base := NewIdsecAuthBase(false, "test", mockAuth)
	base.ActiveProfile = CreateTestProfile("test", "mock_auth", "user1")
	base.ActiveAuthProfile = &auth.IdsecAuthProfile{
		Username:           "user1",
		AuthMethod:         auth.Direct,
		AuthMethodSettings: auth.DirectIdsecAuthMethodSettings{Endpoint: "https://test.example.com"},
	}
	valid := CreateTestToken("valid_token", time.Now().Add(1*time.Hour), "refresh")
	base.setState(valid, base.ActiveProfile, base.ActiveAuthProfile)

	got, err := base.LoadAuthentication(nil, true)
	if err != nil {
		t.Fatalf("LoadAuthentication returned error: %v", err)
	}
	if got == nil || got.Token != "valid_token" {
		t.Fatalf("expected the in-memory token to be preserved, got %+v", got)
	}
	if base.GetToken() == nil || base.GetToken().Token != "valid_token" {
		t.Fatalf("expected stored token to remain 'valid_token', got %+v", base.GetToken())
	}
	if refreshCalled {
		t.Errorf("refresh should not have been attempted for a valid, non-expired in-memory token")
	}
}
