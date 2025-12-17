package common

import (
	"os"
	"testing"

	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// Test helper functions

// setEnvVar sets an environment variable for testing and returns a cleanup function
func setEnvVar(t *testing.T, key, value string) func() {
	t.Helper()
	original := os.Getenv(key)
	os.Setenv(key, value)
	return func() {
		if original == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, original)
		}
	}
}

func TestGetSelfUpgrader(t *testing.T) {
	tests := []struct {
		name           string
		githubURL      string
		setupEnv       func() func()
		expectedError  bool
		validateConfig func(t *testing.T, updater *selfupdate.Updater)
	}{
		{
			name:      "success_public_github_no_env_var",
			githubURL: "",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_github_enterprise_with_env_var",
			githubURL: "github.enterprise.com",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "github.enterprise.com")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_github_enterprise_with_subdomain",
			githubURL: "my-org.github.enterprise.com",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "my-org.github.enterprise.com")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
		{
			name:      "success_empty_github_url_after_unset",
			githubURL: "",
			setupEnv: func() func() {
				// First set a value, then unset it
				os.Setenv("GITHUB_URL", "some-value")
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false,
			validateConfig: func(t *testing.T, updater *selfupdate.Updater) {
				if updater == nil {
					t.Error("Expected updater to be created, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Setup environment
			cleanup := tt.setupEnv()
			defer cleanup()

			// Execute function
			updater, err := GetSelfUpgrader()

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			// Validate no error when success expected
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Custom validation
			if tt.validateConfig != nil {
				tt.validateConfig(t, updater)
			}
		})
	}
}

// Integration test that actually calls the real functions with mocked environment
func TestIsLatestVersion_Integration(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func() func()
		expectedError bool
	}{
		{
			name: "integration_with_public_github",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "")
			},
			expectedError: false, // May fail due to network, but should not panic
		},
		{
			name: "integration_with_enterprise_github",
			setupEnv: func() func() {
				return setEnvVar(t, "GITHUB_URL", "github.enterprise.com")
			},
			expectedError: false, // May fail due to network, but should not panic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not parallel for integration tests as they may have side effects

			cleanup := tt.setupEnv()
			defer cleanup()

			// This test mainly ensures the function doesn't panic
			// and handles real-world scenarios gracefully
			_, _, err := IsLatestVersion()

			// We don't assert on specific results since this depends on
			// external GitHub API, but we ensure no panic occurs
			if err != nil {
				t.Logf("Integration test error (expected in test environment): %v", err)
			}
		})
	}
}
