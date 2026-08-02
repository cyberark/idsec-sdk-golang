package identity

import (
	"encoding/json"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	identitymodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
)

func TestLoadCacheUsesCompletePersistentRefreshState(t *testing.T) {
	keyringToken := signedTestToken(t, jwt.MapClaims{
		"tenant_id": "test-tenant",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	sessionDetails, err := json.Marshal(identitymodels.AdvanceAuthResult{
		Token:        keyringToken,
		RefreshToken: "keyring-refresh-token",
	})
	if err != nil {
		t.Fatalf("failed to marshal session details: %v", err)
	}
	sessionInfo, err := json.Marshal(map[string]interface{}{
		"headers": DefaultHeaders(),
		"cookies": map[string]string{"session": "keyring-cookie"},
	})
	if err != nil {
		t.Fatalf("failed to marshal session info: %v", err)
	}

	mockKeyring := &MockKeyring{
		LoadTokenFunc: func(_ *models.IdsecProfile, postfix string, _ bool) (*auth.IdsecToken, error) {
			switch postfix {
			case "user@test.com_identity":
				return &auth.IdsecToken{
					Token:     string(sessionDetails),
					Username:  "user@test.com",
					ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(time.Hour)),
				}, nil
			case "user@test.com_identity_session":
				return &auth.IdsecToken{
					Token:    string(sessionInfo),
					Username: "user@test.com",
					Endpoint: "https://identity.example.com",
				}, nil
			default:
				t.Fatalf("unexpected keyring postfix %q", postfix)
				return nil, nil
			}
		},
	}

	identityAuth := &IdsecIdentity{
		username: "user@test.com",
		logger:   CreateTestLogger(),
		keyring:  mockKeyring,
		session:  common.NewSimpleIdsecClient("https://fallback.example.com"),
	}
	if !identityAuth.loadCache(CreateTestProfile("test")) {
		t.Fatal("expected complete keyring state to load")
	}
	if !identityAuth.HasRefreshState() {
		t.Fatal("expected loaded keyring state to be refreshable")
	}
	if identityAuth.SessionToken() != keyringToken {
		t.Fatalf("expected keyring token, got %q", identityAuth.SessionToken())
	}
	if identityAuth.IdentityURL() != "https://identity.example.com" {
		t.Fatalf("expected keyring endpoint, got %q", identityAuth.IdentityURL())
	}
	if identityAuth.Session().GetCookies()["session"] != "keyring-cookie" {
		t.Fatal("expected keyring cookies to be restored")
	}
}

func TestLoadRefreshStateUsesInMemoryToken(t *testing.T) {
	identityAuth := &IdsecIdentity{
		username: "user@test.com",
		logger:   CreateTestLogger(),
		session:  common.NewSimpleIdsecClient("https://identity.example.com"),
	}
	expiresAt := commonmodels.IdsecRFC3339Time(time.Now().Add(time.Hour))
	inMemoryToken := signedTestToken(t, jwt.MapClaims{
		"tenant_id": "test-tenant",
		"iat":       time.Now().Unix(),
		"exp":       time.Time(expiresAt).Unix(),
	})
	err := identityAuth.LoadRefreshState(&auth.IdsecToken{
		Token:        inMemoryToken,
		RefreshToken: "in-memory-refresh-token",
		Username:     "user@test.com",
		Endpoint:     "https://identity.example.com",
		AuthMethod:   auth.Identity,
		ExpiresIn:    expiresAt,
	})
	if err != nil {
		t.Fatalf("LoadRefreshState returned an error: %v", err)
	}
	if !identityAuth.HasRefreshState() {
		t.Fatal("expected hydrated in-memory state to be refreshable")
	}
	if identityAuth.SessionToken() != inMemoryToken {
		t.Fatalf("expected in-memory token, got %q", identityAuth.SessionToken())
	}
	if !time.Time(identityAuth.SessionExp()).Equal(time.Time(expiresAt)) {
		t.Fatalf("expected expiration %v, got %v", expiresAt, identityAuth.SessionExp())
	}
}

func TestIncompleteCacheFallsBackToInMemoryRefreshState(t *testing.T) {
	incompleteDetails, err := json.Marshal(identitymodels.AdvanceAuthResult{
		Token: "cached-token-without-refresh-token",
	})
	if err != nil {
		t.Fatalf("failed to marshal incomplete session details: %v", err)
	}
	sessionInfo, err := json.Marshal(map[string]interface{}{
		"headers": DefaultHeaders(),
		"cookies": map[string]string{},
	})
	if err != nil {
		t.Fatalf("failed to marshal session info: %v", err)
	}
	mockKeyring := &MockKeyring{
		LoadTokenFunc: func(_ *models.IdsecProfile, postfix string, _ bool) (*auth.IdsecToken, error) {
			if postfix == "user@test.com_identity" {
				return &auth.IdsecToken{Token: string(incompleteDetails)}, nil
			}
			return &auth.IdsecToken{
				Token:    string(sessionInfo),
				Endpoint: "https://identity.example.com",
			}, nil
		},
	}
	identityAuth := &IdsecIdentity{
		username: "user@test.com",
		logger:   CreateTestLogger(),
		keyring:  mockKeyring,
		session:  common.NewSimpleIdsecClient("https://identity.example.com"),
	}
	if identityAuth.loadCache(CreateTestProfile("test")) {
		t.Fatal("expected incomplete keyring state to be rejected")
	}

	expiresAt := time.Now().Add(time.Hour)
	inMemoryToken := signedTestToken(t, jwt.MapClaims{
		"tenant_id": "test-tenant",
		"iat":       time.Now().Unix(),
		"exp":       expiresAt.Unix(),
	})
	if err := identityAuth.LoadRefreshState(&auth.IdsecToken{
		Token:        inMemoryToken,
		RefreshToken: "in-memory-refresh-token",
		Username:     "user@test.com",
		Endpoint:     "https://identity.example.com",
		AuthMethod:   auth.Identity,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(expiresAt),
	}); err != nil {
		t.Fatalf("failed to load in-memory fallback: %v", err)
	}
	if identityAuth.SessionToken() != inMemoryToken {
		t.Fatal("expected in-memory state to replace incomplete keyring state")
	}
}
