//go:build e2e

package auth

import (
	"os"
	"os/exec"
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

const serviceUserRefreshHelperEnv = "IDSEC_E2E_SERVICE_USER_REFRESH_HELPER"

func requireServiceUserConfig(t *testing.T) *framework.ISPProviderConfig {
	t.Helper()

	config := framework.MustLoadConfig(t)
	if config == nil {
		return nil
	}
	rawConfig, ok := config.AuthProfiles["isp"]
	if !ok {
		t.Skip("Identity service-user refresh E2E requires the ISP auth provider")
	}
	ispConfig, ok := rawConfig.(*framework.ISPProviderConfig)
	require.True(t, ok, "ISP provider has unexpected configuration type %T", rawConfig)
	if ispConfig.AuthMethod != authmodels.IdentityServiceUser {
		t.Skipf(
			"Identity service-user refresh E2E requires IDSEC_E2E_ISP_AUTH_METHOD=identity_service_user, got %q",
			ispConfig.AuthMethod,
		)
	}
	return ispConfig
}

func serviceUserProfile(config *framework.ISPProviderConfig, profileName string) (*models.IdsecProfile, *authmodels.IdsecAuthProfile) {
	authProfile := &authmodels.IdsecAuthProfile{
		Username:   config.Username,
		AuthMethod: authmodels.IdentityServiceUser,
		AuthMethodSettings: &authmodels.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      config.IdentityURL,
			IdentityTenantSubdomain:          config.IdentityTenantSubdomain,
			IdentityAuthorizationApplication: "",
		},
	}
	return &models.IdsecProfile{
		ProfileName:        profileName,
		ProfileDescription: "Isolated Identity service-user refresh E2E profile",
		AuthProfiles: map[string]*authmodels.IdsecAuthProfile{
			"isp": authProfile,
		},
	}, authProfile
}

// TestIdentityServiceUserProactiveRefresh verifies that a near-expiry
// service-user token triggers the complete client-credentials and authorization
// flow using the credential retained by the running authenticator.
func TestIdentityServiceUserProactiveRefresh(t *testing.T) {
	_ = requireServiceUserConfig(t)

	command := exec.Command(
		os.Args[0],
		"-test.run=^TestIdentityServiceUserProactiveRefreshSubprocess$",
		"-test.v",
	)
	command.Env = subprocessEnvironment(map[string]string{
		serviceUserRefreshHelperEnv: "true",
		"IDSEC_BASIC_KEYRING":       "true",
		"IDSEC_KEYRING_FOLDER":      t.TempDir(),
		"IDSEC_E2E_PROFILE_NAME":    framework.RandomResourceName("e2e-service-user-refresh"),
	})

	output, err := command.CombinedOutput()
	require.NoError(t, err, "service-user refresh subprocess failed:\n%s", output)
	t.Logf("service-user refresh subprocess completed:\n%s", output)
}

func TestIdentityServiceUserProactiveRefreshSubprocess(t *testing.T) {
	if os.Getenv(serviceUserRefreshHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	ispConfig := requireServiceUserConfig(t)
	profileName := os.Getenv("IDSEC_E2E_PROFILE_NAME")
	require.NotEmpty(t, profileName, "subprocess profile name is required")
	profile, authProfile := serviceUserProfile(ispConfig, profileName)

	authenticator := idsecauth.NewIdsecISPAuth(true).(*idsecauth.IdsecISPAuth)
	initial, err := authenticator.Authenticate(
		profile,
		authProfile,
		&authmodels.IdsecSecret{Secret: ispConfig.Secret},
		false,
		false,
	)
	require.NoError(t, err, "initial Identity service-user authentication failed")
	require.NotNil(t, initial)
	require.NotEmpty(t, initial.Token)
	initialToken := initial.Token
	initialExpiration := time.Time(initial.ExpiresIn)
	require.True(t, initialExpiration.After(time.Now()), "initial token must expire in the future")

	cacheHitAuthenticator := idsecauth.NewIdsecISPAuth(true).(*idsecauth.IdsecISPAuth)
	cached, err := cacheHitAuthenticator.LoadAuthentication(profile, true)
	require.NoError(t, err, "loading a valid cached service-user token failed")
	require.NotNil(t, cached)
	if cached.Token != initialToken {
		t.Fatal("valid cached service-user token was unexpectedly refreshed")
	}

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
	require.NoError(t, err, "failed to seed a near-expiry service-user token")

	refreshed, err := authenticator.LoadAuthentication(profile, true)
	require.NoError(t, err, "proactive Identity service-user refresh failed")
	require.NotNil(t, refreshed)
	require.NotEmpty(t, refreshed.Token)
	if refreshed.Token == initialToken {
		t.Fatal("service-user refresh did not publish a new access token")
	}
	require.True(
		t,
		time.Time(refreshed.ExpiresIn).After(initialExpiration),
		"refreshed service-user token expiration should advance",
	)

	service, err := directories.NewIdsecIdentityDirectoriesService(authenticator)
	require.NoError(t, err, "failed to create Identity directories service after service-user refresh")
	result, err := service.List(&directoriesmodels.IdsecIdentityListDirectories{})
	require.NoError(t, err, "live Identity request failed after service-user refresh")
	require.NotEmpty(t, result, "expected at least one Identity directory")
}
