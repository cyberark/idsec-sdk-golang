//go:build e2e

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	idsecauth "github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	directories "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestIdentityServiceUserLogin verifies a service user can authenticate through
// the client-credentials and authorization flow and receives a bearer-only token
// with no refresh token and a future expiration.
func TestIdentityServiceUserLogin(t *testing.T) {
	ispConfig := requireServiceUserConfig(t)
	profile, authProfile := serviceUserProfile(ispConfig, framework.RandomResourceName("e2e-service-user-login"))

	authenticator := idsecauth.NewIdsecISPAuth(false)
	token, err := authenticator.Authenticate(
		profile,
		authProfile,
		&authmodels.IdsecSecret{Secret: ispConfig.Secret},
		false,
		false,
	)
	require.NoError(t, err, "Identity service-user login failed")
	require.NotNil(t, token)
	require.NotEmpty(t, token.Token)
	require.Equal(t, "", token.RefreshToken, "service users must not receive a refresh token")
	require.True(t, time.Time(token.ExpiresIn).After(time.Now()), "service-user token must expire in the future")
}

// TestIdentityServiceUserInMemoryReauth verifies that a running no-cache
// authenticator re-authenticates from its in-memory service-user credential when
// the token moves into the refresh grace window.
func TestIdentityServiceUserInMemoryReauth(t *testing.T) {
	ispConfig := requireServiceUserConfig(t)
	profile, authProfile := serviceUserProfile(ispConfig, framework.RandomResourceName("e2e-service-user-memory-reauth"))

	authenticator := idsecauth.NewIdsecISPAuth(false).(*idsecauth.IdsecISPAuth)
	initial, err := authenticator.Authenticate(
		profile,
		authProfile,
		&authmodels.IdsecSecret{Secret: ispConfig.Secret},
		false,
		false,
	)
	require.NoError(t, err, "initial non-cached service-user authentication failed")
	require.NotNil(t, initial)
	require.NotEmpty(t, initial.Token)
	require.False(t, authenticator.CacheAuthentication, "test must run without authentication caching")

	initialToken := initial.Token
	initialExpiration := time.Time(initial.ExpiresIn)
	time.Sleep(1100 * time.Millisecond)
	require.NoError(
		t,
		authenticator.SetTokenExpirationForE2E(time.Now().Add(30*time.Second)),
		"failed to move the in-memory token into the refresh grace window",
	)

	refreshed, err := authenticator.LoadAuthentication(nil, true)
	require.NoError(t, err, "non-cached service-user re-authentication failed")
	require.NotNil(t, refreshed)
	if refreshed.Token == initialToken {
		t.Fatal("non-cached service-user re-auth did not publish a new access token")
	}
	require.True(
		t,
		time.Time(refreshed.ExpiresIn).After(initialExpiration),
		"non-cached refreshed service-user token expiration should advance",
	)
	require.Equal(t, "", refreshed.RefreshToken, "service users must not receive a refresh token")

	service, err := directories.NewIdsecIdentityDirectoriesService(authenticator)
	require.NoError(t, err, "failed to create service after non-cached service-user re-auth")
	result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
	require.NoError(t, err, "live Identity request failed after non-cached service-user re-auth")
	require.NotEmpty(t, result, "expected at least one Identity directory")
}

// TestIdentityServiceUserReactive401Retry invalidates the bearer on a read-only
// service client. The live endpoint should reject it, after which the configured
// refresh callback restores a valid bearer and retries. Service users are
// bearer-only, so cookies are irrelevant here.
func TestIdentityServiceUserReactive401Retry(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		config := framework.MustLoadConfig(t)
		rawConfig, ok := config.AuthProfiles["isp"]
		if !ok {
			t.Skip("service-user reactive 401 E2E requires the ISP auth provider")
		}
		ispConfig, ok := rawConfig.(*framework.ISPProviderConfig)
		require.True(t, ok, "ISP provider has unexpected configuration type %T", rawConfig)
		if ispConfig.AuthMethod != authmodels.IdentityServiceUser {
			t.Skipf("service-user reactive 401 E2E requires IDSEC_E2E_ISP_AUTH_METHOD=identity_service_user, got %q", ispConfig.AuthMethod)
		}

		service, err := ctx.API.IdentityDirectories()
		require.NoError(t, err, "failed to create Identity directories service")
		authenticator := service.ISPAuth()
		token := authenticator.GetToken()
		require.NotNil(t, token)
		require.NotEmpty(t, token.Token)
		validBearer := token.Token

		client := service.ISPClient()
		client.UpdateToken(
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJlMmUtaW52YWxpZCJ9.invalid",
			client.GetTokenType(),
		)
		// Service users are bearer-only; cookies are irrelevant, so unlike the
		// regular-user test we do NOT clear the service client's cookies.
		if client.GetToken() == validBearer {
			t.Fatal("failed to install stale bearer on the service client")
		}

		result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
		require.NoError(t, err, "read-only Identity request did not recover from stale bearer")
		require.NotEmpty(t, result, "expected at least one Identity directory")
		require.NotEqual(
			t,
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJlMmUtaW52YWxpZCJ9.invalid",
			client.GetToken(),
			"client should no longer hold the bogus bearer after reactive refresh",
		)
		require.NotEmpty(t, client.GetToken(), "client should hold a fresh bearer after reactive refresh")
	}, directories.ServiceConfig)
}
