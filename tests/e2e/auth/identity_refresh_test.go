//go:build e2e

package auth

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	idsecauth "github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	directories "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const proactiveRefreshHelperEnv = "IDSEC_E2E_PROACTIVE_REFRESH_HELPER"

func requireRegularIdentityConfig(t *testing.T) (*framework.E2EConfig, *framework.ISPProviderConfig) {
	t.Helper()

	config := framework.MustLoadConfig(t)
	if config == nil {
		return nil, nil
	}
	rawConfig, ok := config.AuthProfiles["isp"]
	if !ok {
		t.Skip("regular Identity refresh E2E requires the ISP auth provider")
	}
	ispConfig, ok := rawConfig.(*framework.ISPProviderConfig)
	require.True(t, ok, "ISP provider has unexpected configuration type %T", rawConfig)
	if ispConfig.AuthMethod != authmodels.Identity {
		t.Skipf("regular Identity refresh E2E requires IDSEC_E2E_ISP_AUTH_METHOD=identity, got %q", ispConfig.AuthMethod)
	}
	return config, ispConfig
}

func regularIdentityProfile(config *framework.ISPProviderConfig, profileName string) (*models.IdsecProfile, *authmodels.IdsecAuthProfile) {
	authProfile := &authmodels.IdsecAuthProfile{
		Username:   config.Username,
		AuthMethod: authmodels.Identity,
		AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{
			IdentityURL:             config.IdentityURL,
			IdentityTenantSubdomain: config.IdentityTenantSubdomain,
			IdentityMFAInteractive:  false,
		},
	}
	return &models.IdsecProfile{
		ProfileName:        profileName,
		ProfileDescription: "Isolated regular Identity refresh E2E profile",
		AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
			"isp": authProfile,
		},
	}, authProfile
}

func subprocessEnvironment(overrides map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := overrides[key]; !overridden {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

// TestIdentityProactiveRefresh verifies the live regular-user
// RefreshPlatformToken flow through LoadAuthentication's expiration-grace path.
// The cache operations run in an isolated subprocess so their environment cannot
// conflict with parallel tests or other E2E packages.
func TestIdentityProactiveRefresh(t *testing.T) {
	_, _ = requireRegularIdentityConfig(t)

	keyringDir := t.TempDir()
	profileName := framework.RandomResourceName("e2e-identity-refresh")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestIdentityProactiveRefreshSubprocess$",
		"-test.v",
	)
	command.Env = subprocessEnvironment(map[string]string{
		proactiveRefreshHelperEnv: "true",
		"IDSEC_BASIC_KEYRING":     "true",
		"IDSEC_KEYRING_FOLDER":    keyringDir,
		"IDSEC_E2E_PROFILE_NAME":  profileName,
	})

	output, err := command.CombinedOutput()
	require.NoError(t, err, "proactive-refresh subprocess failed:\n%s", output)
	t.Logf("proactive-refresh subprocess completed:\n%s", output)
}

// TestIdentityProactiveRefreshSubprocess is invoked only by
// TestIdentityProactiveRefresh with an isolated basic-keyring environment.
func TestIdentityProactiveRefreshSubprocess(t *testing.T) {
	if os.Getenv(proactiveRefreshHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	_, ispConfig := requireRegularIdentityConfig(t)
	profileName := os.Getenv("IDSEC_E2E_PROFILE_NAME")
	require.NotEmpty(t, profileName, "subprocess profile name is required")
	profile, authProfile := regularIdentityProfile(ispConfig, profileName)

	authenticator := idsecauth.NewIdsecISPAuth(true).(*idsecauth.IdsecISPAuth)
	initial, err := authenticator.Authenticate(
		profile,
		authProfile,
		&authmodels.IdsecSecret{Secret: ispConfig.Secret},
		false,
		false,
	)
	require.NoError(t, err, "initial regular Identity authentication failed")
	require.NotNil(t, initial)
	require.NotEmpty(t, initial.Token)
	require.NotEmpty(t, initial.RefreshToken)

	initialToken := initial.Token
	initialRefreshToken := initial.RefreshToken
	initialExpiration := time.Time(initial.ExpiresIn)
	require.True(t, initialExpiration.After(time.Now()), "initial token must expire in the future")

	cacheHitAuthenticator := idsecauth.NewIdsecISPAuth(true).(*idsecauth.IdsecISPAuth)
	cached, err := cacheHitAuthenticator.LoadAuthentication(profile, true)
	require.NoError(t, err, "loading a valid cached Identity token failed")
	require.NotNil(t, cached)
	if cached.Token != initialToken {
		t.Fatal("valid cached token was unexpectedly refreshed")
	}

	// Identity JWT timestamps are commonly second-granular. A short delay keeps
	// token/expiration rotation assertions deterministic without waiting for expiry.
	time.Sleep(1100 * time.Millisecond)

	nearExpiry := *initial
	nearExpiry.ExpiresIn = commonmodels.IdsecRFC3339Time(time.Now().Add(30 * time.Second))
	require.Equal(t, initialExpiration, time.Time(initial.ExpiresIn), "published token must remain immutable")
	outerKeyring := keyring.NewIdsecKeyring("IdsecISPAuth")
	err = outerKeyring.SaveToken(
		profile,
		&nearExpiry,
		authenticator.ResolveCachePostfix(authProfile),
		true,
	)
	require.NoError(t, err, "failed to seed a near-expiry ISP token")

	reloadingAuthenticator := idsecauth.NewIdsecISPAuth(true).(*idsecauth.IdsecISPAuth)
	refreshed, err := reloadingAuthenticator.LoadAuthentication(profile, true)
	require.NoError(t, err, "proactive regular Identity refresh failed")
	require.NotNil(t, refreshed)
	if refreshed.Token == initialToken {
		t.Fatal("proactive refresh did not publish a new access token")
	}
	require.NotEmpty(t, refreshed.RefreshToken)
	require.True(
		t,
		time.Time(refreshed.ExpiresIn).After(initialExpiration),
		"refreshed token expiration should advance",
	)
	if refreshed.RefreshToken == initialRefreshToken {
		t.Log("Identity tenant reused the refresh token; access-token rotation still succeeded")
	}
	cookies, ok := refreshed.Metadata["cookies"].(string)
	require.True(t, ok, "refreshed token should contain serialized cookie metadata")
	require.NotEmpty(t, cookies, "serialized cookie metadata should not be empty")

	service, err := directories.NewIdsecIdentityDirectoriesService(reloadingAuthenticator)
	require.NoError(t, err, "failed to create Identity directories service after refresh")
	require.NotEmpty(t, service.ISPClient().GetCookies(), "refreshed service client should restore session cookies")
	result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
	require.NoError(t, err, "live Identity request failed after proactive refresh")
	require.NotEmpty(t, result, "expected at least one Identity directory")
}

// TestIdentityProactiveRefreshWithoutCache verifies that a running authenticator
// can refresh from its in-memory regular Identity session when no keyring exists.
func TestIdentityProactiveRefreshWithoutCache(t *testing.T) {
	_, ispConfig := requireRegularIdentityConfig(t)
	profile, authProfile := regularIdentityProfile(
		ispConfig,
		framework.RandomResourceName("e2e-identity-memory-refresh"),
	)

	authenticator := idsecauth.NewIdsecISPAuth(false).(*idsecauth.IdsecISPAuth)
	initial, err := authenticator.Authenticate(
		profile,
		authProfile,
		&authmodels.IdsecSecret{Secret: ispConfig.Secret},
		false,
		false,
	)
	require.NoError(t, err, "initial non-cached Identity authentication failed")
	require.NotNil(t, initial)
	require.NotEmpty(t, initial.Token)
	require.NotEmpty(t, initial.RefreshToken)
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
	require.NoError(t, err, "non-cached proactive Identity refresh failed")
	require.NotNil(t, refreshed)
	if refreshed.Token == initialToken {
		t.Fatal("non-cached proactive refresh did not publish a new access token")
	}
	require.True(
		t,
		time.Time(refreshed.ExpiresIn).After(initialExpiration),
		"non-cached refreshed token expiration should advance",
	)
	require.NotEmpty(t, refreshed.RefreshToken)

	service, err := directories.NewIdsecIdentityDirectoriesService(authenticator)
	require.NoError(t, err, "failed to create service after non-cached refresh")
	result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
	require.NoError(t, err, "live Identity request failed after non-cached refresh")
	require.NotEmpty(t, result, "expected at least one Identity directory")
}

// TestIdentityReactive401ReadOnlyRetry invalidates the credentials only on a
// read-only service client. The live endpoint should reject them, after which the
// configured refresh callback restores the authenticator's valid bearer and retries.
func TestIdentityReactive401ReadOnlyRetry(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		_, _ = requireRegularIdentityConfig(t)

		service, err := ctx.API.IdentityDirectories()
		require.NoError(t, err, "failed to create Identity directories service")
		authenticator := service.ISPAuth()
		token := authenticator.GetToken()
		require.NotNil(t, token)
		require.NotEmpty(t, token.Token)

		client := service.ISPClient()
		validBearer := token.Token
		require.NotEmpty(t, client.GetCookies(), "regular Identity client should start with session cookies")
		client.UpdateToken(
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJlMmUtaW52YWxpZCJ9.invalid",
			client.GetTokenType(),
		)
		// Identity endpoints also accept session cookies, so changing only the
		// bearer does not reliably produce a 401. Clear the service client's
		// cookies while leaving the authenticator's token metadata untouched.
		client.SetCookies(map[string]string{})
		if client.GetToken() == validBearer {
			t.Fatal("failed to install stale bearer on the service client")
		}

		result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
		require.NoError(t, err, "read-only Identity request did not recover from stale bearer")
		require.NotEmpty(t, result, "expected at least one Identity directory")
		if client.GetToken() != validBearer {
			t.Fatal("refresh callback did not restore the authenticator's valid bearer")
		}
		require.NotEmpty(t, client.GetCookies(), "refresh callback should restore Identity session cookies")
	}, directories.ServiceConfig)
}

// TestIdentityReactive401RefreshesExpiringAuthenticator verifies the complete
// reactive path: a live 401 invokes the callback, the near-expiry authenticator
// renews its Identity token, and the request retries with the new session.
func TestIdentityReactive401RefreshesExpiringAuthenticator(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		_, _ = requireRegularIdentityConfig(t)

		service, err := ctx.API.IdentityDirectories()
		require.NoError(t, err, "failed to create Identity directories service")
		authenticator := service.ISPAuth()
		initial := authenticator.GetToken()
		require.NotNil(t, initial)
		require.NotEmpty(t, initial.Token)
		initialToken := initial.Token
		initialExpiration := time.Time(initial.ExpiresIn)

		time.Sleep(1100 * time.Millisecond)
		require.NoError(
			t,
			authenticator.SetTokenExpirationForE2E(time.Now().Add(30*time.Second)),
			"failed to move the authenticator token into the refresh grace window",
		)

		client := service.ISPClient()
		client.UpdateToken(
			"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJlMmUtaW52YWxpZCJ9.invalid",
			client.GetTokenType(),
		)
		client.SetCookies(map[string]string{})

		result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
		require.NoError(t, err, "read-only request did not recover through token renewal")
		require.NotEmpty(t, result, "expected at least one Identity directory")

		refreshed := authenticator.GetToken()
		require.NotNil(t, refreshed)
		if refreshed.Token == initialToken {
			t.Fatal("401 callback restored credentials without renewing the near-expiry token")
		}
		if client.GetToken() != refreshed.Token {
			t.Fatal("retried client did not receive the renewed authenticator token")
		}
		require.True(
			t,
			time.Time(refreshed.ExpiresIn).After(initialExpiration),
			"401-triggered refresh should advance token expiration",
		)
		require.NotEmpty(t, client.GetCookies(), "401-triggered refresh should restore session cookies")
	}, directories.ServiceConfig)
}
