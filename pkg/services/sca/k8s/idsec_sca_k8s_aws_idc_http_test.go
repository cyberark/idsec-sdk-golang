package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

// newAWSIDCTestElevateResult returns a valid permission-set elevate result. The
// StartURL is left with no verification URIs on the device-auth response so the
// browser is never opened during tests (handled by the test server).
func newAWSIDCTestElevateResult() *k8smodels.IdsecSCAK8sElevateResult {
	return &k8smodels.IdsecSCAK8sElevateResult{
		WorkspaceID: "201316147283",
		RoleID:      "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
		RoleName:    "MyPermissionSet",
		ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			StartURL:     "https://d-abc.awsapps.com/start",
			SSORegion:    "us-east-1",
		},
	}
}

// pointAWSIDCEndpointsAt overrides the package-level endpoint builders and HTTP
// client to target a single test server, restoring originals on cleanup.
func pointAWSIDCEndpointsAt(t *testing.T, serverURL string) {
	t.Helper()
	origOIDC := awsIDCOIDCEndpoint
	origPortal := awsIDCPortalEndpoint
	origClient := awsIDCHTTPClient

	awsIDCOIDCEndpoint = func(string) string { return serverURL }
	awsIDCPortalEndpoint = func(string) string { return serverURL }
	awsIDCHTTPClient = &http.Client{}

	t.Cleanup(func() {
		awsIDCOIDCEndpoint = origOIDC
		awsIDCPortalEndpoint = origPortal
		awsIDCHTTPClient = origClient
	})
}

func TestEnsureAWSIDCAccessCredentials_HTTPHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/device_authorization":
			_ = json.NewEncoder(w).Encode(awsIDCStartDeviceAuthResponse{
				DeviceCode: "device-code",
				UserCode:   "USER-CODE",
				ExpiresIn:  600,
				Interval:   1,
			})
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(awsIDCCreateTokenResponse{
				AccessToken: "oidc-access-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			})
		case r.URL.Path == "/federation/credentials":
			if got := r.Header.Get("x-amz-sso_bearer_token"); got != "oidc-access-token" {
				t.Errorf("missing/incorrect bearer token header: %q", got)
			}
			if got := r.URL.Query().Get("account_id"); got != "201316147283" {
				t.Errorf("account_id = %q", got)
			}
			if got := r.URL.Query().Get("role_name"); got != "MyPermissionSet" {
				t.Errorf("role_name = %q", got)
			}
			_ = json.NewEncoder(w).Encode(awsIDCGetRoleCredentialsResponse{
				RoleCredentials: awsIDCRoleCredentials{
					AccessKeyID:     "AKIATEST",
					SecretAccessKey: "secret",
					SessionToken:    "token",
				},
			})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	creds, accessToken, _, _, err := EnsureAWSIDCAccessCredentials(newAWSIDCTestElevateResult(), false, nil)
	if err != nil {
		t.Fatalf("EnsureAWSIDCAccessCredentials: %v", err)
	}
	if accessToken != "oidc-access-token" {
		t.Fatalf("accessToken = %q", accessToken)
	}
	if creds.AWSAccessKey != "AKIATEST" || creds.AWSSecretAccessKey != "secret" || creds.AWSSessionToken != "token" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestEnsureAWSIDCAccessCredentials_HTTPPollingPending(t *testing.T) {
	var tokenCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device_authorization":
			_ = json.NewEncoder(w).Encode(awsIDCStartDeviceAuthResponse{
				DeviceCode: "device-code",
				UserCode:   "USER-CODE",
				ExpiresIn:  600,
				Interval:   1,
			})
		case "/token":
			tokenCalls++
			if tokenCalls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(awsIDCErrorResponse{Error: awsIDCErrAuthorizationPending})
				return
			}
			_ = json.NewEncoder(w).Encode(awsIDCCreateTokenResponse{AccessToken: "tok", ExpiresIn: 3600})
		case "/federation/credentials":
			_ = json.NewEncoder(w).Encode(awsIDCGetRoleCredentialsResponse{
				RoleCredentials: awsIDCRoleCredentials{AccessKeyID: "AKIA", SecretAccessKey: "s", SessionToken: "t"},
			})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	creds, _, _, _, err := EnsureAWSIDCAccessCredentials(newAWSIDCTestElevateResult(), false, nil)
	if err != nil {
		t.Fatalf("EnsureAWSIDCAccessCredentials: %v", err)
	}
	if tokenCalls < 2 {
		t.Fatalf("expected polling to retry /token, calls = %d", tokenCalls)
	}
	if creds.AWSAccessKey != "AKIA" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestEnsureAWSIDCAccessCredentials_HTTPGetRoleCredentialsForbiddenReturnsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device_authorization":
			_ = json.NewEncoder(w).Encode(awsIDCStartDeviceAuthResponse{DeviceCode: "dc", ExpiresIn: 600, Interval: 1})
		case "/token":
			_ = json.NewEncoder(w).Encode(awsIDCCreateTokenResponse{AccessToken: "cached-token", ExpiresIn: 3600})
		case "/federation/credentials":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(awsIDCErrorResponse{Error: "ForbiddenException"})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	creds, accessToken, _, _, err := EnsureAWSIDCAccessCredentials(newAWSIDCTestElevateResult(), false, nil)
	if err == nil {
		t.Fatal("expected error from GetRoleCredentials 403")
	}
	if creds != nil {
		t.Fatalf("expected nil creds on error, got %+v", creds)
	}
	// The access token must be returned even on failure so callers can cache it
	// and avoid re-triggering device authorization on retry.
	if accessToken != "cached-token" {
		t.Fatalf("expected access token returned on failure, got %q", accessToken)
	}
	if !strings.Contains(err.Error(), "GetRoleCredentials failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveAWSIDCOIDCAccessToken_UsesCache(t *testing.T) {
	// When the cache returns a token, no HTTP calls should be made.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected HTTP call to %s during cached-token path", r.URL.Path)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	cache := &AWSIDCOIDCCache{
		LoadAccessToken: func() (string, string, time.Time, bool) {
			return "cached", "", time.Now().Add(time.Hour), true
		},
	}

	token, _, _, err := resolveAWSIDCOIDCAccessToken(context.Background(), "us-east-1", newAWSIDCTestElevateResult().ClientDetails, false, cache)
	if err != nil {
		t.Fatalf("resolveAWSIDCOIDCAccessToken: %v", err)
	}
	if token != "cached" {
		t.Fatalf("expected cached token, got %q", token)
	}
}

// TestResolveAWSIDCOIDCAccessToken_UsesRefreshToken verifies that when the cached
// access token is expired but a refresh token is present, the refresh_token grant
// is used (single /token call) and the device_authorization flow is NOT started.
func TestResolveAWSIDCOIDCAccessToken_UsesRefreshToken(t *testing.T) {
	var deviceAuthCalls, tokenCalls int
	var gotGrantType, gotRefreshToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device_authorization":
			deviceAuthCalls++
			http.Error(w, "device auth must not be called when a refresh token is available", http.StatusInternalServerError)
		case "/token":
			tokenCalls++
			var req awsIDCCreateTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			gotGrantType = req.GrantType
			gotRefreshToken = req.RefreshToken
			_ = json.NewEncoder(w).Encode(awsIDCCreateTokenResponse{
				AccessToken:  "refreshed-access-token",
				RefreshToken: "rotated-refresh-token",
				ExpiresIn:    3600,
			})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	cache := &AWSIDCOIDCCache{
		LoadAccessToken: func() (string, string, time.Time, bool) {
			// access token expired (ok=false) but refresh token still available
			return "", "stored-refresh-token", time.Time{}, false
		},
	}

	token, refreshToken, _, err := resolveAWSIDCOIDCAccessToken(context.Background(), "us-east-1", newAWSIDCTestElevateResult().ClientDetails, false, cache)
	if err != nil {
		t.Fatalf("resolveAWSIDCOIDCAccessToken: %v", err)
	}
	if deviceAuthCalls != 0 {
		t.Fatalf("expected no device_authorization calls, got %d", deviceAuthCalls)
	}
	if tokenCalls != 1 {
		t.Fatalf("expected exactly one /token call, got %d", tokenCalls)
	}
	if gotGrantType != awsIDCRefreshTokenGrantType {
		t.Fatalf("expected grantType %q, got %q", awsIDCRefreshTokenGrantType, gotGrantType)
	}
	if gotRefreshToken != "stored-refresh-token" {
		t.Fatalf("expected stored refresh token to be sent, got %q", gotRefreshToken)
	}
	if token != "refreshed-access-token" {
		t.Fatalf("expected refreshed access token, got %q", token)
	}
	if refreshToken != "rotated-refresh-token" {
		t.Fatalf("expected rotated refresh token, got %q", refreshToken)
	}
}

// TestResolveAWSIDCOIDCAccessToken_RefreshFailsFallsBackToDeviceAuth verifies the
// safe fallback: when the refresh_token grant fails, the device flow runs.
func TestResolveAWSIDCOIDCAccessToken_RefreshFailsFallsBackToDeviceAuth(t *testing.T) {
	var deviceAuthCalls int
	var tokenGrantTypes []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/device_authorization":
			deviceAuthCalls++
			_ = json.NewEncoder(w).Encode(awsIDCStartDeviceAuthResponse{
				DeviceCode: "device-code",
				UserCode:   "USER-CODE",
				ExpiresIn:  600,
				Interval:   1,
			})
		case "/token":
			var req awsIDCCreateTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			tokenGrantTypes = append(tokenGrantTypes, req.GrantType)
			if req.GrantType == awsIDCRefreshTokenGrantType {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(awsIDCErrorResponse{Error: "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(awsIDCCreateTokenResponse{
				AccessToken: "device-access-token",
				ExpiresIn:   3600,
			})
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pointAWSIDCEndpointsAt(t, srv.URL)

	cache := &AWSIDCOIDCCache{
		LoadAccessToken: func() (string, string, time.Time, bool) {
			return "", "expired-refresh-token", time.Time{}, false
		},
	}

	token, _, _, err := resolveAWSIDCOIDCAccessToken(context.Background(), "us-east-1", newAWSIDCTestElevateResult().ClientDetails, false, cache)
	if err != nil {
		t.Fatalf("resolveAWSIDCOIDCAccessToken: %v", err)
	}
	if deviceAuthCalls != 1 {
		t.Fatalf("expected device authorization fallback (1 call), got %d", deviceAuthCalls)
	}
	if len(tokenGrantTypes) < 2 || tokenGrantTypes[0] != awsIDCRefreshTokenGrantType || tokenGrantTypes[len(tokenGrantTypes)-1] != awsIDCDeviceCodeGrantType {
		t.Fatalf("expected refresh_token grant then device_code grant, got %v", tokenGrantTypes)
	}
	if token != "device-access-token" {
		t.Fatalf("expected device-flow access token, got %q", token)
	}
}

// TestCapExpiryToElevateSession verifies the OIDC token expiry never exceeds the
// Elevate sessionExpTime.
func TestCapExpiryToElevateSession(t *testing.T) {
	base := time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC)

	// sessionExpTime earlier than token expiry → capped to session.
	sessionEarlier := base.Add(10 * time.Minute)
	got := capExpiryToElevateSession(base.Add(time.Hour), sessionEarlier.Format(time.RFC3339))
	if !got.Equal(sessionEarlier) {
		t.Fatalf("expected cap to sessionExpTime %s, got %s", sessionEarlier, got)
	}

	// sessionExpTime later than token expiry → token expiry unchanged.
	tokenExp := base.Add(15 * time.Minute)
	got = capExpiryToElevateSession(tokenExp, base.Add(time.Hour).Format(time.RFC3339))
	if !got.Equal(tokenExp) {
		t.Fatalf("expected token expiry %s unchanged, got %s", tokenExp, got)
	}

	// missing/unparseable sessionExpTime → token expiry unchanged.
	got = capExpiryToElevateSession(tokenExp, "")
	if !got.Equal(tokenExp) {
		t.Fatalf("expected token expiry %s unchanged on empty sessionExpTime, got %s", tokenExp, got)
	}
}
