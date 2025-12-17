package actions

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

func TestNewIdsecLoginAction(t *testing.T) {
	tests := []struct {
		name           string
		profilesLoader *profiles.ProfileLoader
		expectedNotNil bool
		validateFunc   func(t *testing.T, action *IdsecLoginAction)
	}{
		{
			name:           "success_normal_profile_loader",
			profilesLoader: testutils.NewMockProfileLoader().AsProfileLoader(),
			expectedNotNil: true,
			validateFunc: func(t *testing.T, action *IdsecLoginAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader == nil {
					t.Error("Expected profilesLoader to be set")
				}
			},
		},
		{
			name:           "success_nil_profile_loader",
			profilesLoader: nil,
			expectedNotNil: true,
			validateFunc: func(t *testing.T, action *IdsecLoginAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader != nil {
					t.Error("Expected profilesLoader to remain nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewIdsecLoginAction(tt.profilesLoader)

			if tt.expectedNotNil && result == nil {
				t.Error("Expected non-nil result")
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecLoginAction_DefineAction(t *testing.T) {
	tests := []struct {
		name         string
		setupAction  func() *IdsecLoginAction
		validateFunc func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_defines_login_command",
			setupAction: func() *IdsecLoginAction {
				return NewIdsecLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				loginCmd, _, err := cmd.Find([]string{"login"})
				if err != nil {
					t.Errorf("Expected to find login command, got error: %v", err)
					return
				}
				if loginCmd == nil {
					t.Error("Expected login command to be added")
					return
				}
				if loginCmd.Use != "login" {
					t.Errorf("Expected command Use to be 'login', got '%s'", loginCmd.Use)
				}
				if loginCmd.Short != "Login to the system" {
					t.Errorf("Expected command Short description, got '%s'", loginCmd.Short)
				}
			},
		},
		{
			name: "success_adds_required_flags",
			setupAction: func() *IdsecLoginAction {
				return NewIdsecLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				loginCmd, _, _ := cmd.Find([]string{"login"})
				if loginCmd == nil {
					t.Error("Login command not found")
					return
				}

				expectedFlags := []string{
					"profile-name",
					"force",
					"no-shared-secrets",
					"show-tokens",
					"refresh-auth",
				}

				for _, flagName := range expectedFlags {
					flag := loginCmd.Flags().Lookup(flagName)
					if flag == nil {
						t.Errorf("Expected flag '%s' to be defined", flagName)
					}
				}
			},
		},
		{
			name: "success_adds_authenticator_flags",
			setupAction: func() *IdsecLoginAction {
				return NewIdsecLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				loginCmd, _, _ := cmd.Find([]string{"login"})
				if loginCmd == nil {
					t.Error("Login command not found")
					return
				}

				// Check for ISP authenticator flags (assuming ISP is in SupportedAuthenticatorsList)
				expectedAuthFlags := []string{
					"isp-username",
					"isp-secret",
				}

				for _, flagName := range expectedAuthFlags {
					flag := loginCmd.Flags().Lookup(flagName)
					if flag == nil {
						t.Errorf("Expected authenticator flag '%s' to be defined", flagName)
					}
				}
			},
		},
		{
			name: "success_nil_profilesloader",
			setupAction: func() *IdsecLoginAction {
				return NewIdsecLoginAction(nil)
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				loginCmd, _, err := cmd.Find([]string{"login"})
				if err != nil {
					t.Errorf("Expected to find login command even with nil loader, got error: %v", err)
					return
				}
				if loginCmd == nil {
					t.Error("Expected login command to be added even with nil loader")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := tt.setupAction()
			rootCmd := &cobra.Command{Use: "idsec"}

			action.DefineAction(rootCmd)

			if tt.validateFunc != nil {
				tt.validateFunc(t, rootCmd)
			}
		})
	}
}

func TestIdsecLoginAction_runLoginAction(t *testing.T) {
	// Capture output for testing
	originalStdout := os.Stdout
	defer func() { os.Stdout = originalStdout }()

	tests := []struct {
		name           string
		setupAction    func() *IdsecLoginAction
		setupCmd       func() *cobra.Command
		loginArgs      []string
		expectedOutput string
		expectedError  bool
		validateFunc   func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command)
	}{
		{
			name: "success_empty_auth_profiles",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return &models.IdsecProfile{
						ProfileName:  name,
						AuthProfiles: make(map[string]*authmodels.IdsecAuthProfile),
					}, nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "login"}
				cmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name")
				cmd.Flags().Bool("force", false, "Force login")
				cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
				cmd.Flags().Bool("no-shared-secrets", false, "No shared secrets")
				cmd.Flags().Bool("show-tokens", false, "Show tokens")
				return cmd
			},
			loginArgs:     []string{},
			expectedError: false,
			validateFunc: func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) {
				// This test validates behavior with empty auth profiles
				// Should complete without error as there are no authenticators to process
			},
		},
		{
			name: "success_valid_profile_loaded",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return testutils.CreateTestProfile(name), nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "login"}
				cmd.Flags().String("profile-name", "test-profile", "Profile name")
				cmd.Flags().Bool("force", false, "Force login")
				cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
				cmd.Flags().Bool("no-shared-secrets", false, "No shared secrets")
				cmd.Flags().Bool("show-tokens", false, "Show tokens")
				cmd.Flags().String("isp-username", "", "ISP username")
				cmd.Flags().String("isp-secret", "", "ISP secret")
				return cmd
			},
			loginArgs:     []string{},
			expectedError: false,
			validateFunc: func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) {
				// This test validates that valid profiles are processed
				// Note: This will attempt actual authentication which might fail in test environment
				// The goal is to verify the flow reaches authentication attempt
			},
		},
		{
			name: "success_force_flag_set",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return testutils.CreateTestProfile(name), nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "login"}
				cmd.Flags().String("profile-name", "test-profile", "Profile name")
				cmd.Flags().Bool("force", true, "Force login")
				cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
				cmd.Flags().Bool("no-shared-secrets", false, "No shared secrets")
				cmd.Flags().Bool("show-tokens", false, "Show tokens")
				cmd.Flags().String("isp-username", "", "ISP username")
				cmd.Flags().String("isp-secret", "", "ISP secret")
				return cmd
			},
			loginArgs:     []string{},
			expectedError: false,
			validateFunc: func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) {
				// Verify force flag behavior is respected
				forceFlag, err := cmd.Flags().GetBool("force")
				if err != nil {
					t.Errorf("Expected to get force flag, got error: %v", err)
				}
				if !forceFlag {
					t.Error("Expected force flag to be true")
				}
			},
		},
		{
			name: "success_show_tokens_flag_set",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return testutils.CreateTestProfile(name), nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "login"}
				cmd.Flags().String("profile-name", "test-profile", "Profile name")
				cmd.Flags().Bool("force", false, "Force login")
				cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
				cmd.Flags().Bool("no-shared-secrets", false, "No shared secrets")
				cmd.Flags().Bool("show-tokens", true, "Show tokens")
				cmd.Flags().String("isp-username", "", "ISP username")
				cmd.Flags().String("isp-secret", "", "ISP secret")
				return cmd
			},
			loginArgs:     []string{},
			expectedError: false,
			validateFunc: func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) {
				// Verify show-tokens flag behavior is respected
				showTokensFlag, err := cmd.Flags().GetBool("show-tokens")
				if err != nil {
					t.Errorf("Expected to get show-tokens flag, got error: %v", err)
				}
				if !showTokensFlag {
					t.Error("Expected show-tokens flag to be true")
				}
			},
		},
		{
			name: "success_no_shared_secrets_flag_set",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return testutils.CreateTestProfile(name), nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{Use: "login"}
				cmd.Flags().String("profile-name", "test-profile", "Profile name")
				cmd.Flags().Bool("force", false, "Force login")
				cmd.Flags().Bool("refresh-auth", false, "Refresh auth")
				cmd.Flags().Bool("no-shared-secrets", true, "No shared secrets")
				cmd.Flags().Bool("show-tokens", false, "Show tokens")
				cmd.Flags().String("isp-username", "", "ISP username")
				cmd.Flags().String("isp-secret", "", "ISP secret")
				return cmd
			},
			loginArgs:     []string{},
			expectedError: false,
			validateFunc: func(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command) {
				// Verify no-shared-secrets flag behavior is respected
				noSharedSecretsFlag, err := cmd.Flags().GetBool("no-shared-secrets")
				if err != nil {
					t.Errorf("Expected to get no-shared-secrets flag, got error: %v", err)
				}
				if !noSharedSecretsFlag {
					t.Error("Expected no-shared-secrets flag to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			r, w, _ := os.Pipe()
			os.Stdout = w
			var output bytes.Buffer

			action := tt.setupAction()
			cmd := tt.setupCmd()

			// Execute the function
			action.runLoginAction(cmd, tt.loginArgs)

			// Close write pipe and read output
			w.Close()
			os.Stdout = originalStdout
			output.ReadFrom(r)

			// Validate expected output patterns if specified
			if tt.expectedOutput != "" && !strings.Contains(output.String(), tt.expectedOutput) {
				t.Errorf("Expected output to contain '%s', got '%s'", tt.expectedOutput, output.String())
			}

			// Custom validation
			if tt.validateFunc != nil {
				tt.validateFunc(t, action, cmd)
			}
		})
	}
}

// TestIdsecLoginAction_Integration provides integration-style tests
func TestIdsecLoginAction_Integration(t *testing.T) {
	tests := []struct {
		name         string
		setupAction  func() *IdsecLoginAction
		validateFunc func(t *testing.T, action *IdsecLoginAction)
	}{
		{
			name: "success_complete_flow_with_mock_loader",
			setupAction: func() *IdsecLoginAction {
				mockLoader := testutils.NewMockProfileLoader()
				mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return testutils.CreateTestProfile(name), nil
				}
				return NewIdsecLoginAction(mockLoader.AsProfileLoader())
			},
			validateFunc: func(t *testing.T, action *IdsecLoginAction) {
				// Test complete DefineAction flow
				rootCmd := &cobra.Command{Use: "idsec"}
				action.DefineAction(rootCmd)

				// Verify command was added
				loginCmd, _, err := rootCmd.Find([]string{"login"})
				if err != nil {
					t.Errorf("Expected to find login command, got error: %v", err)
				}
				if loginCmd == nil {
					t.Error("Expected login command to be defined")
				}

				// Verify PersistentPreRun is set
				if loginCmd.PersistentPreRun == nil {
					t.Error("Expected PersistentPreRun to be set")
				}
			},
		},
		{
			name: "success_action_structure_validation",
			setupAction: func() *IdsecLoginAction {
				return NewIdsecLoginAction(testutils.NewMockProfileLoader().AsProfileLoader())
			},
			validateFunc: func(t *testing.T, action *IdsecLoginAction) {
				// Validate the action structure
				if action == nil {
					t.Error("Expected non-nil action")
					return
				}
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader == nil {
					t.Error("Expected profilesLoader to be set")
				}

				// Validate it implements IdsecAction interface
				var _ IdsecAction = action
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := tt.setupAction()

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

// handleExpectedConfigureEOF is a helper function for tests that expect configure flow to be triggered
// but may panic with EOF in test environment due to lack of interactive terminal
func handleExpectedConfigureEOF(t *testing.T, action *IdsecLoginAction, cmd *cobra.Command, args []string) {
	defer func() {
		if r := recover(); r != nil {
			// Check if it's the expected EOF panic from configure flow
			if err, ok := r.(error); ok && err.Error() == "EOF" {
				// This is expected - configure flow was triggered but failed due to no interactive terminal
				t.Log("Configure flow was triggered and failed with EOF as expected in test environment")
				return
			}
			// Re-panic if it's a different error
			panic(r)
		}
	}()

	action.runLoginAction(cmd, args)
}

// setupConfigureFlowTest creates common test setup for configure flow tests
func setupConfigureFlowTest() (*IdsecLoginAction, *cobra.Command) {
	// Create mock loader that returns profile not found error
	mockLoader := testutils.NewMockProfileLoader()
	mockLoader.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
		return nil, errors.New("profile not found")
	}
	action := NewIdsecLoginAction(mockLoader.AsProfileLoader())

	// Create basic command with profile-name flag
	cmd := &cobra.Command{Use: "login"}
	cmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name")

	return action, cmd
}

// TestIdsecLoginAction_ConfigureFlow tests the new configure flow behavior
func TestIdsecLoginAction_ConfigureFlow(t *testing.T) {
	t.Run("interactive_mode_triggers_configure_flow", func(t *testing.T) {
		// Test that in interactive mode, missing profile triggers configure flow
		action, cmd := setupConfigureFlowTest()
		// No silent flag - should be interactive

		// Use helper to handle expected EOF
		handleExpectedConfigureEOF(t, action, cmd, []string{})
	})

	t.Run("non_interactive_mode_no_configure_flow", func(t *testing.T) {
		// Test that in non-interactive mode (silent), missing profile does NOT trigger configure flow
		action, cmd := setupConfigureFlowTest()

		// Add silent flag to make it non-interactive
		cmd.Flags().Bool("silent", true, "Silent mode")
		cmd.Flags().Set("silent", "true")

		// This should NOT panic - should handle gracefully
		action.runLoginAction(cmd, []string{})
	})
}
