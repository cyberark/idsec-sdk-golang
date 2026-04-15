//go:build e2e

package framework

import (
	"fmt"
	"os"
	"strings"
	"testing"

	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// E2EConfig holds the configuration for E2E tests loaded from environment variables.
type E2EConfig struct {
	// AuthProfiles maps authenticator name -> loaded provider config.
	// Only contains providers that have credentials configured AND are expected.
	AuthProfiles map[string]AuthProviderConfig

	// ExpectedAuthTypes is the parsed IDSEC_E2E_AUTH_EXPECT value.
	// Empty slice means "all" (build whatever has credentials).
	ExpectedAuthTypes []string

	// Skip indicates whether E2E tests should be skipped
	Skip bool
}

// LoadConfig loads E2E configuration from environment variables.
// It iterates the auth provider registry, applies the IDSEC_E2E_AUTH_EXPECT filter,
// and loads credentials for each matching provider. Returns an error if expected
// providers are missing credentials or if no providers could be loaded.
func LoadConfig() (*E2EConfig, error) {
	// Check if E2E tests should be skipped
	if skip := os.Getenv("IDSEC_E2E_SKIP"); strings.ToLower(skip) == "true" {
		return &E2EConfig{Skip: true}, nil
	}

	// Parse IDSEC_E2E_AUTH_EXPECT (default: "all")
	expectedAuthTypes := parseExpectedAuthTypes(os.Getenv("IDSEC_E2E_AUTH_EXPECT"))

	// Apply backward-compatibility mapping for old env vars
	applyBackwardCompatEnvVars()

	// Load auth profiles from the registry
	authProfiles, err := loadAuthProfiles(expectedAuthTypes)
	if err != nil {
		return nil, err
	}

	if len(authProfiles) == 0 {
		return nil, fmt.Errorf("no auth providers configured; set IDSEC_E2E_ISP_* and/or IDSEC_E2E_PVWA_* env vars")
	}

	return &E2EConfig{
		AuthProfiles:      authProfiles,
		ExpectedAuthTypes: expectedAuthTypes,
		Skip:              false,
	}, nil
}

// parseExpectedAuthTypes parses the IDSEC_E2E_AUTH_EXPECT value.
// "all" or empty -> nil (meaning build all configured providers).
// "isp" -> ["isp"]; "isp,pvwa" -> ["isp", "pvwa"].
func parseExpectedAuthTypes(raw string) []string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "all" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// applyBackwardCompatEnvVars maps old-style env vars to the new per-provider vars
// when the new vars are not already set.
func applyBackwardCompatEnvVars() {
	oldUsername := os.Getenv("IDSEC_E2E_USERNAME")
	oldSecret := os.Getenv("IDSEC_E2E_SECRET")
	oldAuthMethod := strings.ToLower(os.Getenv("IDSEC_E2E_AUTH_METHOD"))

	// Only apply if old vars are present and new vars are not
	if oldUsername == "" || oldSecret == "" {
		return
	}

	switch oldAuthMethod {
	case "pvwa":
		// Map old vars to PVWA provider
		setEnvIfEmpty("IDSEC_E2E_PVWA_USERNAME", oldUsername)
		setEnvIfEmpty("IDSEC_E2E_PVWA_SECRET", oldSecret)
		setEnvIfEmpty("IDSEC_E2E_PVWA_URL", os.Getenv("IDSEC_E2E_PVWA_URL"))
		setEnvIfEmpty("IDSEC_E2E_PVWA_LOGIN_METHOD", os.Getenv("IDSEC_E2E_PVWA_LOGIN_METHOD"))
	default:
		// identity, identity_service_user, or empty -> ISP provider
		setEnvIfEmpty("IDSEC_E2E_ISP_USERNAME", oldUsername)
		setEnvIfEmpty("IDSEC_E2E_ISP_SECRET", oldSecret)
		if oldAuthMethod != "" {
			setEnvIfEmpty("IDSEC_E2E_ISP_AUTH_METHOD", oldAuthMethod)
		}
		setEnvIfEmpty("IDSEC_E2E_ISP_IDENTITY_URL", os.Getenv("IDSEC_E2E_IDENTITY_URL"))
		setEnvIfEmpty("IDSEC_E2E_ISP_IDENTITY_TENANT_SUBDOMAIN", os.Getenv("IDSEC_E2E_IDENTITY_TENANT_SUBDOMAIN"))
	}
}

// setEnvIfEmpty sets the env var only if it is not already set and the value is non-empty.
func setEnvIfEmpty(key, value string) {
	if value == "" {
		return
	}
	if os.Getenv(key) == "" {
		os.Setenv(key, value)
	}
}

// loadAuthProfiles iterates the provider registry and loads configs.
// If expectedAuthTypes is nil (all mode), loads every provider whose env vars are present.
// If expectedAuthTypes lists specific names, loads only those and errors if any are missing.
func loadAuthProfiles(expectedAuthTypes []string) (map[string]AuthProviderConfig, error) {
	profiles := make(map[string]AuthProviderConfig)

	if len(expectedAuthTypes) == 0 {
		// "all" mode: try every registered provider
		for name, provider := range authProviderRegistry {
			cfg := provider.Load()
			if cfg == nil {
				continue // No credentials for this provider, skip
			}
			if err := cfg.Validate(); err != nil {
				return nil, fmt.Errorf("auth provider '%s' has invalid config: %w", name, err)
			}
			profiles[name] = cfg
		}
	} else {
		// Specific providers requested
		for _, name := range expectedAuthTypes {
			provider, ok := authProviderRegistry[name]
			if !ok {
				return nil, fmt.Errorf("unknown auth provider '%s' in IDSEC_E2E_AUTH_EXPECT (registered: %v)", name, registeredProviderNames())
			}
			cfg := provider.Load()
			if cfg == nil {
				return nil, fmt.Errorf("auth provider '%s' is expected but credentials are not configured", name)
			}
			if err := cfg.Validate(); err != nil {
				return nil, fmt.Errorf("auth provider '%s' has invalid config: %w", name, err)
			}
			profiles[name] = cfg
		}
	}

	return profiles, nil
}

// registeredProviderNames returns the names of all registered auth providers.
func registeredProviderNames() []string {
	names := make([]string, 0, len(authProviderRegistry))
	for name := range authProviderRegistry {
		names = append(names, name)
	}
	return names
}

// MustLoadConfig loads E2E configuration or skips the test if configuration is missing.
// This is the recommended way to load config in tests as it gracefully handles missing credentials.
func MustLoadConfig(t *testing.T) *E2EConfig {
	t.Helper()

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("E2E auth configuration error: %v", err)
		return nil
	}

	if config.Skip {
		t.Skip("Skipping E2E test: IDSEC_E2E_SKIP is set to true")
		return nil
	}

	return config
}

// Validate checks if the configuration is valid and complete.
func (c *E2EConfig) Validate() error {
	if c.Skip {
		return nil
	}

	if len(c.AuthProfiles) == 0 {
		return fmt.Errorf("no auth profiles configured")
	}

	for name, profile := range c.AuthProfiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("auth profile '%s' validation failed: %w", name, err)
		}
	}

	return nil
}

// HasAuthProfile returns true if the specified authenticator profile is available.
func (c *E2EConfig) HasAuthProfile(name string) bool {
	_, ok := c.AuthProfiles[name]
	return ok
}

// AvailableAuthTypes returns the names of all configured authenticator profiles.
func (c *E2EConfig) AvailableAuthTypes() []string {
	names := make([]string, 0, len(c.AuthProfiles))
	for name := range c.AuthProfiles {
		names = append(names, name)
	}
	return names
}

// AuthMethod returns the auth method for backward compatibility.
// If only one profile is loaded, returns its auth method.
// Deprecated: Use AuthProfiles directly instead.
func (c *E2EConfig) AuthMethod() authmodels.IdsecAuthMethod {
	for name := range c.AuthProfiles {
		switch name {
		case "pvwa":
			return authmodels.PVWA
		case "isp":
			if cfg, ok := c.AuthProfiles[name].(*ISPProviderConfig); ok {
				return cfg.AuthMethod
			}
			return authmodels.IdentityServiceUser
		}
	}
	return authmodels.IdentityServiceUser
}
