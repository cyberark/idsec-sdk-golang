//go:build e2e

package framework

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// AuthProviderConfig holds the loaded configuration for a single auth provider.
// Each provider type implements its own concrete struct.
type AuthProviderConfig interface {
	// ProviderName returns the authenticator name (e.g., "isp", "pvwa").
	ProviderName() string
	// Validate checks that the config is complete and returns an error if not.
	Validate() error
}

// AuthProviderLoader loads config from env vars and returns nil if credentials are absent.
type AuthProviderLoader func() AuthProviderConfig

// AuthProviderAuthenticator creates and authenticates using the loaded config.
type AuthProviderAuthenticator func(t *testing.T, config AuthProviderConfig) (auth.IdsecAuth, error)

// AuthProvider bundles a loader and authenticator for one auth type.
type AuthProvider struct {
	Name         string
	Load         AuthProviderLoader
	Authenticate AuthProviderAuthenticator
}

// authProviderRegistry is the global registry of auth providers.
var authProviderRegistry = map[string]*AuthProvider{}

// RegisterAuthProvider registers an auth provider by name.
func RegisterAuthProvider(provider *AuthProvider) {
	authProviderRegistry[provider.Name] = provider
}

func init() {
	RegisterAuthProvider(newISPProvider())
	RegisterAuthProvider(newPVWAProvider())
}

// --- ISP Provider ---

// ISPProviderConfig holds the loaded ISP configuration from env vars.
type ISPProviderConfig struct {
	Username                string
	Secret                  string
	AuthMethod              authmodels.IdsecAuthMethod
	IdentityURL             string
	IdentityTenantSubdomain string
}

// ProviderName returns "isp".
func (c *ISPProviderConfig) ProviderName() string { return "isp" }

// Validate checks that required ISP fields are set.
func (c *ISPProviderConfig) Validate() error {
	if c.Username == "" {
		return fmt.Errorf("ISP username is required (IDSEC_E2E_ISP_USERNAME)")
	}
	if c.Secret == "" {
		return fmt.Errorf("ISP secret is required (IDSEC_E2E_ISP_SECRET)")
	}
	return nil
}

// newISPProvider creates the ISP auth provider with its loader and authenticator.
func newISPProvider() *AuthProvider {
	return &AuthProvider{
		Name: "isp",
		Load: func() AuthProviderConfig {
			username := os.Getenv("IDSEC_E2E_ISP_USERNAME")
			secret := os.Getenv("IDSEC_E2E_ISP_SECRET")
			if username == "" || secret == "" {
				return nil
			}

			authMethodStr := strings.ToLower(os.Getenv("IDSEC_E2E_ISP_AUTH_METHOD"))
			var authMethod authmodels.IdsecAuthMethod
			switch authMethodStr {
			case "identity":
				authMethod = authmodels.Identity
			case "identity_service_user", "":
				authMethod = authmodels.IdentityServiceUser
			default:
				authMethod = authmodels.IdentityServiceUser
			}

			return &ISPProviderConfig{
				Username:                username,
				Secret:                  secret,
				AuthMethod:              authMethod,
				IdentityURL:             os.Getenv("IDSEC_E2E_ISP_IDENTITY_URL"),
				IdentityTenantSubdomain: os.Getenv("IDSEC_E2E_ISP_IDENTITY_TENANT_SUBDOMAIN"),
			}
		},
		Authenticate: func(t *testing.T, config AuthProviderConfig) (auth.IdsecAuth, error) {
			t.Helper()
			cfg := config.(*ISPProviderConfig)

			authenticator := auth.NewIdsecISPAuth(false)

			var authMethodSettings authmodels.IdsecAuthMethodSettings
			switch cfg.AuthMethod {
			case authmodels.Identity:
				authMethodSettings = &authmodels.IdentityIdsecAuthMethodSettings{
					IdentityURL:             cfg.IdentityURL,
					IdentityTenantSubdomain: cfg.IdentityTenantSubdomain,
					IdentityMFAInteractive:  false,
				}
				t.Logf("ISP: Authenticating as %s using Identity method", cfg.Username)
			case authmodels.IdentityServiceUser:
				authMethodSettings = &authmodels.IdentityServiceUserIdsecAuthMethodSettings{
					IdentityURL:                      cfg.IdentityURL,
					IdentityTenantSubdomain:          cfg.IdentityTenantSubdomain,
					IdentityAuthorizationApplication: "",
				}
				t.Logf("ISP: Authenticating as %s using IdentityServiceUser method", cfg.Username)
			default:
				return nil, fmt.Errorf("ISP provider: unsupported auth method: %v", cfg.AuthMethod)
			}

			authProfile := &authmodels.IdsecAuthProfile{
				Username:           cfg.Username,
				AuthMethod:         cfg.AuthMethod,
				AuthMethodSettings: authMethodSettings,
			}
			secret := &authmodels.IdsecSecret{
				Secret: cfg.Secret,
			}

			_, err := authenticator.Authenticate(nil, authProfile, secret, false, false)
			if err != nil {
				return nil, fmt.Errorf("ISP authentication failed: %w", err)
			}

			t.Log("ISP authentication successful")
			return authenticator, nil
		},
	}
}

// --- PVWA Provider ---

// PVWAProviderConfig holds the loaded PVWA configuration from env vars.
type PVWAProviderConfig struct {
	Username    string
	Secret      string
	PVWAURL     string
	LoginMethod string
}

// ProviderName returns "pvwa".
func (c *PVWAProviderConfig) ProviderName() string { return "pvwa" }

// Validate checks that required PVWA fields are set.
func (c *PVWAProviderConfig) Validate() error {
	if c.Username == "" {
		return fmt.Errorf("PVWA username is required (IDSEC_E2E_PVWA_USERNAME)")
	}
	if c.Secret == "" {
		return fmt.Errorf("PVWA secret is required (IDSEC_E2E_PVWA_SECRET)")
	}
	if c.PVWAURL == "" {
		return fmt.Errorf("PVWA URL is required (IDSEC_E2E_PVWA_URL)")
	}
	validMethods := []string{"cyberark", "ldap", "windows"}
	found := false
	for _, m := range validMethods {
		if c.LoginMethod == m {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid PVWA login method: %s (must be 'cyberark', 'ldap', or 'windows')", c.LoginMethod)
	}
	return nil
}

// newPVWAProvider creates the PVWA auth provider with its loader and authenticator.
func newPVWAProvider() *AuthProvider {
	return &AuthProvider{
		Name: "pvwa",
		Load: func() AuthProviderConfig {
			username := os.Getenv("IDSEC_E2E_PVWA_USERNAME")
			secret := os.Getenv("IDSEC_E2E_PVWA_SECRET")
			if username == "" || secret == "" {
				return nil
			}

			pvwaURL := os.Getenv("IDSEC_E2E_PVWA_URL")
			loginMethod := strings.ToLower(os.Getenv("IDSEC_E2E_PVWA_LOGIN_METHOD"))
			if loginMethod == "" {
				loginMethod = "ldap"
			}

			return &PVWAProviderConfig{
				Username:    username,
				Secret:      secret,
				PVWAURL:     pvwaURL,
				LoginMethod: loginMethod,
			}
		},
		Authenticate: func(t *testing.T, config AuthProviderConfig) (auth.IdsecAuth, error) {
			t.Helper()
			cfg := config.(*PVWAProviderConfig)

			authenticator := auth.NewIdsecPVWAAuth(false)

			authMethodSettings := &authmodels.PVWAIdsecAuthMethodSettings{
				PVWAURL:         cfg.PVWAURL,
				PVWALoginMethod: cfg.LoginMethod,
			}
			t.Logf("PVWA: Authenticating to %s using %s method", cfg.PVWAURL, cfg.LoginMethod)

			authProfile := &authmodels.IdsecAuthProfile{
				Username:           cfg.Username,
				AuthMethod:         authmodels.PVWA,
				AuthMethodSettings: authMethodSettings,
			}
			secret := &authmodels.IdsecSecret{
				Secret: cfg.Secret,
			}

			_, err := authenticator.Authenticate(nil, authProfile, secret, false, false)
			if err != nil {
				return nil, fmt.Errorf("PVWA authentication failed: %w", err)
			}

			t.Log("PVWA authentication successful")
			return authenticator, nil
		},
	}
}
