package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func setupServiceUserISPAuth(t *testing.T, identityURL string, expiredToken string) *IdsecISPAuth {
	t.Helper()

	const appName = "testapp"
	profile := CreateTestProfile("test", "isp", "user@test.com")
	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.IdentityServiceUser,
		AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      identityURL,
			IdentityTenantSubdomain:          "tenant",
			IdentityAuthorizationApplication: appName,
		},
	}
	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	authInstance.setSecret(&auth.IdsecSecret{Secret: "service-token"})
	authInstance.setState(
		CreateTestToken(expiredToken, time.Now().Add(-time.Hour), ""),
		profile,
		authProfile,
	)
	return authInstance
}

// refreshClientLikeISP mirrors isp.RefreshClient without importing isp (avoids test import cycle).
func refreshClientLikeISP(client *common.IdsecClient, ispAuth *IdsecISPAuth) error {
	token, err := ispAuth.LoadAuthentication(nil, true)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("failed to refresh client: no token available after authentication")
	}
	client.UpdateToken(token.Token, client.GetTokenType())
	return nil
}

// TestLoadAuthentication_refresh_expired_service_user is the proactive refresh path when
// refreshAuth=true and the in-memory token is past expiry (LoadAuthentication → performRefreshAuthentication).
func TestLoadAuthentication_refresh_expired_service_user_integration(t *testing.T) {
	t.Parallel()

	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	identityServer := newServiceUserIdentityServer(t, "testapp", freshIDToken)
	defer identityServer.Close()

	authInstance := setupServiceUserISPAuth(t, identityServer.URL, "expired_token")
	token, err := authInstance.LoadAuthentication(nil, true)
	if err != nil {
		t.Fatalf("LoadAuthentication failed: %v", err)
	}
	if token == nil || token.Token != freshIDToken {
		t.Fatalf("Expected refreshed token %q, got %#v", freshIDToken, token)
	}
}

// TestRefreshClient_like_success verifies the explicit refresh path used by SDK services
// before API calls (isp.RefreshClient → LoadAuthentication(nil, true)).
func TestRefreshClient_like_success(t *testing.T) {
	t.Parallel()

	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	identityServer := newServiceUserIdentityServer(t, "testapp", freshIDToken)
	defer identityServer.Close()

	authInstance := setupServiceUserISPAuth(t, identityServer.URL, "expired_token")
	client := common.NewIdsecClient("https://example.com", "expired_token", "Bearer", "Authorization", nil, nil, "", false)

	if err := refreshClientLikeISP(client, authInstance); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if client.GetToken() != freshIDToken {
		t.Fatalf("Expected refreshed token on client, got %q", client.GetToken())
	}
}

// TestRefreshClient_proactive_before_request simulates services that call RefreshClient
// before each operation when the token is already expired.
func TestRefreshClient_proactive_before_request(t *testing.T) {
	t.Parallel()

	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	identityServer := newServiceUserIdentityServer(t, "testapp", freshIDToken)
	defer identityServer.Close()

	var apiCalls int
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		if r.Header.Get("Authorization") != "Bearer "+freshIDToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	authInstance := setupServiceUserISPAuth(t, identityServer.URL, "expired_token")
	client := common.NewIdsecClient(apiServer.URL, "expired_token", "Bearer", "Authorization", nil, nil, "", false)
	if err := refreshClientLikeISP(client, authInstance); err != nil {
		t.Fatalf("proactive refresh failed: %v", err)
	}

	resp, err := client.Get(context.Background(), "/resource", nil)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200, got %d", resp.StatusCode)
	}
	if apiCalls != 1 {
		t.Fatalf("Expected 1 API call after proactive refresh, got %d", apiCalls)
	}
}

// TestIdsecClient_reactive_401_refreshes_identity_service_user is the production failure path:
// stale bearer on an in-process client, API returns 401, refresh callback re-authenticates, retry succeeds.
func TestIdsecClient_reactive_401_refreshes_identity_service_user(t *testing.T) {
	t.Parallel()

	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	identityServer := newServiceUserIdentityServer(t, "testapp", freshIDToken)
	defer identityServer.Close()

	var apiCalls int
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		if r.Header.Get("Authorization") != "Bearer "+freshIDToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"token expired"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer apiServer.Close()

	authInstance := setupServiceUserISPAuth(t, identityServer.URL, "expired_token")
	client := common.NewIdsecClient(
		apiServer.URL,
		"expired_token",
		"Bearer",
		"Authorization",
		nil,
		func(c *common.IdsecClient) error {
			return refreshClientLikeISP(c, authInstance)
		},
		"",
		false,
	)

	resp, err := client.Get(context.Background(), "/resource", nil)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 after 401 refresh, got %d", resp.StatusCode)
	}
	if apiCalls != 2 {
		t.Fatalf("Expected 2 API calls (401 then retry), got %d", apiCalls)
	}
}

// TestIdsecClient_reactive_401_POST verifies refresh retry on mutating requests (Terraform apply path).
func TestIdsecClient_reactive_401_POST(t *testing.T) {
	t.Parallel()

	freshIDToken := serviceUserTestIDToken(t, "user@test.com")
	identityServer := newServiceUserIdentityServer(t, "testapp", freshIDToken)
	defer identityServer.Close()

	var apiCalls int
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+freshIDToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer apiServer.Close()

	authInstance := setupServiceUserISPAuth(t, identityServer.URL, "expired_token")
	client := common.NewIdsecClient(
		apiServer.URL,
		"expired_token",
		"Bearer",
		"Authorization",
		nil,
		func(c *common.IdsecClient) error {
			return refreshClientLikeISP(c, authInstance)
		},
		"",
		false,
	)

	resp, err := client.Post(context.Background(), "/resource", map[string]string{"name": "policy"})
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 after 401 refresh, got %d", resp.StatusCode)
	}
	if apiCalls != 2 {
		t.Fatalf("Expected 2 API calls (401 then retry), got %d", apiCalls)
	}
}

// TestIdsecClient_reactive_401_refresh_fails_without_secret verifies pre-fix behavior when
// the service token was not retained: refresh callback errors instead of silently succeeding.
func TestIdsecClient_reactive_401_refresh_fails_without_secret(t *testing.T) {
	t.Parallel()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer apiServer.Close()

	authInstance := NewIdsecISPAuth(false).(*IdsecISPAuth)
	profile := CreateTestProfile("test", "isp", "user@test.com")
	authProfile := &auth.IdsecAuthProfile{
		Username:   "user@test.com",
		AuthMethod: auth.IdentityServiceUser,
		AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      "https://identity.example.com",
			IdentityTenantSubdomain:          "tenant",
			IdentityAuthorizationApplication: "testapp",
		},
	}
	authInstance.setState(CreateTestToken("expired", time.Now().Add(-time.Hour), ""), profile, authProfile)

	client := common.NewIdsecClient(
		apiServer.URL,
		"expired",
		"Bearer",
		"Authorization",
		nil,
		func(c *common.IdsecClient) error {
			return refreshClientLikeISP(c, authInstance)
		},
		"",
		false,
	)

	resp, err := client.Get(context.Background(), "/resource", nil)
	if err == nil {
		defer resp.Body.Close()
		t.Fatal("Expected error when refresh cannot re-authenticate without secret")
	}
}
