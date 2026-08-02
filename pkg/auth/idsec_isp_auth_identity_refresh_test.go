package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestIdentityRefreshUsesInMemoryStateWhenCachingDisabled(t *testing.T) {
	currentToken := serviceUserTestIDToken(t, "current-user@test.com")
	freshToken := serviceUserTestIDToken(t, "refreshed-user@test.com")
	const freshRefreshToken = "fresh-refresh-token"

	identityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/OAuth2/RefreshPlatformToken" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  "idToken-test-tenant-id",
			Value: freshToken,
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "refreshToken-test-tenant-id",
			Value: freshRefreshToken,
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer identityServer.Close()

	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	profile := CreateTestProfile("test", "isp", "user@test.com")
	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.Identity,
		AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{
			IdentityURL: identityServer.URL,
		},
	}
	inMemoryToken := &auth.IdsecToken{
		Token:        currentToken,
		TokenType:    auth.JWT,
		Username:     authProfile.Username,
		Endpoint:     identityServer.URL,
		AuthMethod:   auth.Identity,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(time.Now().Add(-time.Minute)),
		RefreshToken: "current-refresh-token",
		Metadata:     map[string]interface{}{},
	}

	authInstance.setState(inMemoryToken, profile, authProfile)
	refreshed, err := authInstance.LoadAuthentication(nil, true)
	if err != nil {
		t.Fatalf("identity refresh failed: %v", err)
	}
	if refreshed.Token != freshToken {
		t.Fatalf("expected refreshed token %q, got %q", freshToken, refreshed.Token)
	}
	if refreshed.RefreshToken != freshRefreshToken {
		t.Fatalf("expected refreshed refresh token %q, got %q", freshRefreshToken, refreshed.RefreshToken)
	}
	if refreshed.AuthMethod != auth.Identity {
		t.Fatalf("expected auth method %q, got %q", auth.Identity, refreshed.AuthMethod)
	}
}

func TestIdentityRefreshRejectsIncompleteInMemoryState(t *testing.T) {
	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.Identity,
		AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{
			IdentityURL: "https://identity.example.com",
		},
	}

	_, err := authInstance.performIdentityRefreshAuthentication(
		CreateTestProfile("test", "isp", "user@test.com"),
		authProfile,
		&auth.IdsecToken{
			Token:     serviceUserTestIDToken(t, "user@test.com"),
			Endpoint:  "https://identity.example.com",
			ExpiresIn: commonmodels.IdsecRFC3339Time(time.Now().Add(-time.Minute)),
		},
	)
	if err == nil {
		t.Fatal("expected missing refresh token to return an error")
	}
}
