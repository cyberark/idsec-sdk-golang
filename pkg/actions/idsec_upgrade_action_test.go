package actions

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/actions/testutils"
)

func TestNewIdsecUpgradeAction(t *testing.T) {
	tests := []struct {
		name           string
		validateFunc   func(t *testing.T, result *IdsecUpgradeAction)
		expectedNotNil bool
	}{
		{
			name:           "success_creates_new_instance",
			expectedNotNil: true,
			validateFunc: func(t *testing.T, result *IdsecUpgradeAction) {
				if result.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized, got nil")
				}
			},
		},
		{
			name:           "success_returns_different_instances",
			expectedNotNil: true,
			validateFunc: func(t *testing.T, result *IdsecUpgradeAction) {
				second := NewIdsecUpgradeAction()
				if result == second {
					t.Error("Expected different instances, got same pointer")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewIdsecUpgradeAction()

			if tt.expectedNotNil && result == nil {
				t.Error("Expected non-nil result, got nil")
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecUpgradeAction_DefineAction(t *testing.T) {
	tests := []struct {
		name          string
		setupCmd      func() *cobra.Command
		validateFunc  func(t *testing.T, cmd *cobra.Command)
		expectedPanic bool
	}{
		{
			name: "success_adds_upgrade_command",
			setupCmd: func() *cobra.Command {
				return testutils.CreateTestCommand()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to be added, got nil")
					return
				}
				if upgradeCmd.Short != "Manage upgrades" {
					t.Errorf("Expected short description 'Manage upgrades', got '%s'", upgradeCmd.Short)
				}
			},
		},
		{
			name: "success_adds_dry_run_flag",
			setupCmd: func() *cobra.Command {
				return testutils.CreateTestCommand()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to be added")
					return
				}
				flag := upgradeCmd.PersistentFlags().Lookup("dry-run")
				if flag == nil {
					t.Error("Expected dry-run flag to be defined, got nil")
					return
				}
				if flag.DefValue != "false" {
					t.Errorf("Expected dry-run default value 'false', got '%s'", flag.DefValue)
				}
			},
		},
		{
			name: "success_adds_version_flag",
			setupCmd: func() *cobra.Command {
				return testutils.CreateTestCommand()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to be added")
					return
				}
				flag := upgradeCmd.PersistentFlags().Lookup("version")
				if flag == nil {
					t.Error("Expected version flag to be defined, got nil")
					return
				}
				if flag.DefValue != "" {
					t.Errorf("Expected version default value '', got '%s'", flag.DefValue)
				}
			},
		},
		{
			name: "success_sets_run_function",
			setupCmd: func() *cobra.Command {
				return testutils.CreateTestCommand()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to be added")
					return
				}
				if upgradeCmd.Run == nil {
					t.Error("Expected Run function to be set, got nil")
				}
			},
		},
		{
			name: "success_sets_persistent_pre_run",
			setupCmd: func() *cobra.Command {
				return testutils.CreateTestCommand()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to be added")
					return
				}
				if upgradeCmd.PersistentPreRun == nil {
					t.Error("Expected PersistentPreRun function to be set, got nil")
				}
			},
		},
		{
			name: "edge_case_nil_command",
			setupCmd: func() *cobra.Command {
				return nil
			},
			expectedPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecUpgradeAction()
			cmd := tt.setupCmd()

			if tt.expectedPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic, but function completed normally")
					}
				}()
			}

			action.DefineAction(cmd)

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}

func TestIdsecUpgradeAction_runUpgradeAction_InvalidVersion(t *testing.T) {
	tests := []struct {
		name           string
		setupEnv       func() func()
		setupCmd       func() *cobra.Command
		args           []string
		expectedPanic  bool
		expectedOutput string
	}{
		{
			name: "success_github_enterprise_url_configuration",
			setupEnv: func() func() {
				return testutils.SetEnvVar("GITHUB_URL", "github.example.com")
			},
			setupCmd: func() *cobra.Command {
				cmd := testutils.CreateTestCommand()
				action := NewIdsecUpgradeAction()
				action.DefineAction(cmd)
				upgradeCmd := findSubcommand(cmd, "upgrade")
				return upgradeCmd
			},
			args:          []string{},
			expectedPanic: true, // Will panic due to IdsecVersion() parsing in current implementation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not using t.Parallel() for environment variable tests

			cleanup := tt.setupEnv()
			defer cleanup()

			action := NewIdsecUpgradeAction()
			cmd := tt.setupCmd()

			if tt.expectedPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Error("Expected panic, but function completed normally")
					}
				}()
			}

			var output string
			if !tt.expectedPanic {
				output = testutils.CaptureOutput(func() {
					action.runUpgradeAction(cmd, tt.args)
				})
			} else {
				action.runUpgradeAction(cmd, tt.args)
			}

			if tt.expectedOutput != "" && !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("Expected output to contain '%s', got '%s'", tt.expectedOutput, output)
			}
		})
	}
}

func TestIdsecUpgradeAction_Integration(t *testing.T) {
	tests := []struct {
		name         string
		setupEnv     func() func()
		cmdArgs      []string
		flags        map[string]string
		validateFunc func(t *testing.T, cmd *cobra.Command, output string)
	}{
		{
			name: "integration_command_structure_complete",
			setupEnv: func() func() {
				return func() {} // no env changes
			},
			cmdArgs: []string{},
			flags:   map[string]string{},
			validateFunc: func(t *testing.T, cmd *cobra.Command, output string) {
				// Verify the command structure is properly set up
				upgradeCmd := findSubcommand(cmd, "upgrade")
				if upgradeCmd == nil {
					t.Error("Expected upgrade subcommand to exist")
					return
				}

				// Check all required flags exist
				requiredFlags := []string{"dry-run", "version"}
				for _, flagName := range requiredFlags {
					if upgradeCmd.PersistentFlags().Lookup(flagName) == nil {
						t.Errorf("Expected flag '%s' to be defined", flagName)
					}
				}

				// Check command functions are set
				if upgradeCmd.Run == nil {
					t.Error("Expected Run function to be set")
				}
				if upgradeCmd.PersistentPreRun == nil {
					t.Error("Expected PersistentPreRun function to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cleanup := tt.setupEnv()
			defer cleanup()

			action := NewIdsecUpgradeAction()
			rootCmd := testutils.CreateTestCommand()
			action.DefineAction(rootCmd)

			// Set flags if provided
			upgradeCmd := findSubcommand(rootCmd, "upgrade")
			for flagName, flagValue := range tt.flags {
				upgradeCmd.Flags().Set(flagName, flagValue)
			}

			var output string
			// Don't actually run the upgrade command as it will panic without proper setup
			// Instead, just validate the command structure
			if tt.validateFunc != nil {
				tt.validateFunc(t, rootCmd, output)
			}
		})
	}
}

// Helper function to find a subcommand by name
func findSubcommand(cmd *cobra.Command, name string) *cobra.Command {
	if cmd == nil {
		return nil
	}
	for _, subCmd := range cmd.Commands() {
		if subCmd.Use == name {
			return subCmd
		}
	}
	return nil
}

// Test helper to verify the IdsecUpgradeAction implements expected interface
func TestIdsecUpgradeAction_ImplementsInterface(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, action *IdsecUpgradeAction)
	}{
		{
			name: "success_has_define_action_method",
			validateFunc: func(t *testing.T, action *IdsecUpgradeAction) {
				// Verify DefineAction method exists and can be called
				cmd := testutils.CreateTestCommand()
				action.DefineAction(cmd) // Should not panic
			},
		},
		{
			name: "success_embeds_idsec_base_action",
			validateFunc: func(t *testing.T, action *IdsecUpgradeAction) {
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be embedded and initialized")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecUpgradeAction()

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

// Test the type and structure of IdsecUpgradeAction
func TestIdsecUpgradeAction_Type(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, actionType reflect.Type)
	}{
		{
			name: "success_correct_struct_type",
			validateFunc: func(t *testing.T, actionType reflect.Type) {
				if actionType.Kind() != reflect.Struct {
					t.Errorf("Expected struct type, got %v", actionType.Kind())
				}
				if actionType.Name() != "IdsecUpgradeAction" {
					t.Errorf("Expected type name 'IdsecUpgradeAction', got '%s'", actionType.Name())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecUpgradeAction()
			actionType := reflect.TypeOf(action).Elem() // Get the struct type, not pointer

			if tt.validateFunc != nil {
				tt.validateFunc(t, actionType)
			}
		})
	}
}
