package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func serviceUserTestIDToken(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"tenant_id": "test-tenant-id",
		"subdomain": "test-subdomain",
		"sub":       subject,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-signing-key"))
	if err != nil {
		t.Fatalf("failed to sign test jwt: %v", err)
	}
	return signed
}

func newServiceUserIdentityServer(t *testing.T, appName string, idToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/OAuth2/Token/"+appName:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"mock_access_token"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/OAuth2/Authorize/"+appName:
			w.Header().Set("Location", fmt.Sprintf("https://cyberark.cloud/redirect#id_token=%s", idToken))
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestIdsecISPAuth_performIdentityServiceUserRefreshAuthentication_success(t *testing.T) {
	t.Parallel()

	const appName = "testapp"
	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	server := newServiceUserIdentityServer(t, appName, freshIDToken)
	defer server.Close()

	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	authInstance.setSecret(&auth.IdsecSecret{Secret: "service-token"})

	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.IdentityServiceUser,
		AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      server.URL,
			IdentityTenantSubdomain:          "tenant",
			IdentityAuthorizationApplication: appName,
		},
	}
	expiredToken := CreateTestToken("expired_token", time.Now().Add(-time.Hour), "")
	expiredToken.AuthMethod = auth.IdentityServiceUser

	result, err := authInstance.performIdentityServiceUserRefreshAuthentication(
		CreateTestProfile("test", "isp", "user@test.com"),
		authProfile,
		expiredToken,
	)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil token")
	}
	if result.Token != freshIDToken {
		t.Errorf("Expected refreshed id_token, got %q", result.Token)
	}
	if result.AuthMethod != auth.IdentityServiceUser {
		t.Errorf("Expected AuthMethod %q, got %q", auth.IdentityServiceUser, result.AuthMethod)
	}
	if time.Time(result.ExpiresIn).Before(time.Now()) {
		t.Errorf("Expected future expiry, got %v", result.ExpiresIn)
	}
}

func TestIdsecISPAuth_LoadAuthentication_refreshes_expired_service_user_token(t *testing.T) {
	t.Parallel()

	const appName = "testapp"
	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	server := newServiceUserIdentityServer(t, appName, freshIDToken)
	defer server.Close()

	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	profile := CreateTestProfile("test", "isp", "user@test.com")
	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.IdentityServiceUser,
		AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      server.URL,
			IdentityTenantSubdomain:          "tenant",
			IdentityAuthorizationApplication: appName,
		},
	}
	authInstance.setSecret(&auth.IdsecSecret{Secret: "service-token"})
	authInstance.setState(
		CreateTestToken("expired_token", time.Now().Add(-time.Hour), ""),
		profile,
		authProfile,
	)

	result, err := authInstance.LoadAuthentication(nil, true)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil token after refresh")
	}
	if result.Token != freshIDToken {
		t.Errorf("Expected refreshed token %q, got %q", freshIDToken, result.Token)
	}
	if !strings.Contains(result.Token, ".") {
		t.Errorf("Expected JWT-shaped token, got %q", result.Token)
	}
}
