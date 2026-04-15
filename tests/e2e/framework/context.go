//go:build e2e

package framework

import (
	"fmt"
	"os"
	"slices"
	"testing"

	api "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// TestContext provides a unified context for E2E tests with authenticated SDK access
// and automatic resource cleanup.
type TestContext struct {
	// T is the testing.T instance for the current test
	T *testing.T

	// API is the authenticated IDSEC SDK client
	API *api.IdsecAPI

	// Config holds the E2E test configuration
	Config *E2EConfig

	// Logger is the SDK logger instance
	Logger *common.IdsecLogger

	// cleanup manages the LIFO cleanup stack
	cleanup *CleanupStack
}

// NewTestContext creates a new test context with authentication and cleanup management.
// It automatically skips the test if E2E configuration is missing or invalid.
//
// Prefer using Run for most tests since it wraps context creation, auth checks,
// and cleanup handling.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//	    ctx := framework.NewTestContext(t)
//	    defer ctx.Cleanup()
//	    // ... test code using ctx.API ...
//	}
func NewTestContext(t *testing.T) *TestContext {
	t.Helper()

	// Load configuration (will skip test if missing)
	config := MustLoadConfig(t)
	if config == nil {
		return nil
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		t.Skipf("Invalid E2E configuration: %v", err)
		return nil
	}

	// Create logger
	logger := common.GetLogger("E2ETest", common.Unknown)

	// Create cleanup stack
	cleanupStack := NewCleanupStack(t)

	// Create and authenticate all configured providers
	authenticators, err := createAuthenticators(t, config)
	if err != nil {
		t.Fatalf("Failed to create authenticators: %v", err)
	}
	if len(authenticators) == 0 {
		t.Fatal("No authenticators configured")
	}

	// Create SDK API instance with all authenticators
	apiClient, err := api.NewIdsecAPI(authenticators, nil)
	if err != nil {
		t.Fatalf("Failed to create IDSEC API client: %v", err)
	}

	t.Logf("E2E test context initialized successfully with %d authenticator(s): %v",
		len(authenticators), config.AvailableAuthTypes())

	return &TestContext{
		T:       t,
		API:     apiClient,
		Config:  config,
		Logger:  logger,
		cleanup: cleanupStack,
	}
}

// Run creates a TestContext, validates service auth compatibility, and executes the
// test function with automatic cleanup.
func Run(t *testing.T, fn func(ctx *TestContext), configs ...services.IdsecServiceConfig) {
	t.Helper()

	ctx := NewTestContext(t)
	if ctx == nil {
		return
	}

	for _, config := range configs {
		ctx.RequireServiceAuth(config)
	}

	defer ctx.Cleanup()
	fn(ctx)
}

// createAuthenticators iterates all configured auth profiles and creates+authenticates
// each one using the provider registry.
func createAuthenticators(t *testing.T, config *E2EConfig) ([]auth.IdsecAuth, error) {
	t.Helper()

	var authenticators []auth.IdsecAuth

	for name, profileConfig := range config.AuthProfiles {
		provider, ok := authProviderRegistry[name]
		if !ok {
			return nil, fmt.Errorf("unknown auth provider: %s", name)
		}
		authenticator, err := provider.Authenticate(t, profileConfig)
		if err != nil {
			return nil, fmt.Errorf("%s authentication failed: %w", name, err)
		}
		authenticators = append(authenticators, authenticator)
		t.Logf("%s authenticator created and authenticated", name)
	}

	return authenticators, nil
}

// RequireServiceAuth skips the test if the service's required authenticators are not
// available in the current test context.
func (ctx *TestContext) RequireServiceAuth(config services.IdsecServiceConfig) {
	ctx.T.Helper()

	if len(config.RequiredAuthenticatorNames) == 0 {
		return
	}

	available := ctx.AvailableAuthTypes()

	for _, required := range config.RequiredAuthenticatorNames {
		if !slices.Contains(available, required) {
			ctx.T.Fatalf("Auth error: service '%s' requires '%s' authenticator (available: %v)",
				config.ServiceName, required, available)
		}
	}
}

// AvailableAuthTypes returns the names of all configured authenticators.
func (ctx *TestContext) AvailableAuthTypes() []string {
	return ctx.Config.AvailableAuthTypes()
}

// HasAuthenticator returns true if the specified authenticator is available.
func (ctx *TestContext) HasAuthenticator(name string) bool {
	return ctx.Config.HasAuthProfile(name)
}

// TrackResource registers a cleanup function for a resource.
// The cleanup will be executed in LIFO order when Cleanup() is called.
//
// Example:
//
//	ctx.TrackResource(func() error {
//	    return ctx.API.SiaAccess().DeleteConnector(connectorID)
//	})
func (ctx *TestContext) TrackResource(cleanupFn func() error) {
	ctx.cleanup.Push("custom cleanup", cleanupFn)
}

// TrackResourceWithName registers a named cleanup function for a resource.
// This provides better logging during cleanup.
func (ctx *TestContext) TrackResourceWithName(name string, cleanupFn func() error) {
	ctx.cleanup.Push(name, cleanupFn)
}

// TrackResourceByType is a convenience method for tracking resources by type and ID.
func (ctx *TestContext) TrackResourceByType(resourceType, resourceID string, cleanupFn func() error) {
	ctx.cleanup.TrackResource(resourceType, resourceID, cleanupFn)
}

// Cleanup executes all registered cleanup functions in LIFO order.
// This should be called with defer immediately after creating the TestContext.
//
// Example:
//
//	ctx := framework.NewTestContext(t)
//	defer ctx.Cleanup()
func (ctx *TestContext) Cleanup() {
	if ctx == nil || ctx.cleanup == nil {
		return
	}
	ctx.cleanup.ExecuteAll()
}

// SkipIfCI skips the test if running in a CI environment.
// This is useful for tests that require interactive input or local resources.
func (ctx *TestContext) SkipIfCI() {
	ctx.T.Helper()
	if os.Getenv("CI") != "" {
		ctx.T.Skip("Skipping test in CI environment")
	}
}

// Profile returns the IDSEC profile being used by the API client.
func (ctx *TestContext) Profile() *models.IdsecProfile {
	return ctx.API.Profile()
}

// SetCleanupFailOnError configures whether cleanup errors should cause the test to fail.
// If set to true (default), cleanup errors will cause the test to fail.
// If set to false, cleanup errors will only be logged as warnings and the test will not fail.
//
// Example:
//
//	ctx := framework.NewTestContext(t)
//	ctx.SetCleanupFailOnError(false) // Only log warnings, don't fail test
//	defer ctx.Cleanup()
func (ctx *TestContext) SetCleanupFailOnError(fail bool) {
	if ctx == nil || ctx.cleanup == nil {
		return
	}
	ctx.cleanup.SetFailOnError(fail)
}
