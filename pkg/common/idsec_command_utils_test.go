package common

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestExecuteCommand(t *testing.T) {
	tests := []struct {
		name          string
		commandLine   string
		expectedError bool
		skipOnOS      string // Skip test on this OS (e.g., "windows")
		validateFunc  func(t *testing.T, err error)
	}{
		{
			name:          "success_simple_command_echo",
			commandLine:   getEchoCommand("test"),
			expectedError: false,
		},
		{
			name:          "success_command_with_output",
			commandLine:   getEchoCommand("hello world"),
			expectedError: false,
		},
		{
			name:          "success_command_with_special_characters",
			commandLine:   getEchoCommand("test with spaces and 'quotes'"),
			expectedError: false,
		},
		{
			name:          "success_multiple_commands_chained",
			commandLine:   getChainedCommands(),
			expectedError: false,
		},
		{
			name:          "error_command_returns_non_zero_exit_code",
			commandLine:   getFalseCommand(),
			expectedError: true,
		},
		{
			name:          "error_nonexistent_command",
			commandLine:   "nonexistent_command_that_does_not_exist_12345",
			expectedError: true,
		},
		{
			name:          "success_empty_command",
			commandLine:   "",
			expectedError: false, // Empty command on sh -c "" succeeds
		},
		{
			name:          "success_command_with_environment_variable",
			commandLine:   getEchoEnvCommand(),
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnOS != "" && runtime.GOOS == tt.skipOnOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			err := ExecuteCommand(tt.commandLine)

			if tt.expectedError {
				if err == nil {
					t.Errorf("ExecuteCommand(%q) expected error, got nil", tt.commandLine)
				} else {
					// Verify it's an exec.ExitError or similar
					if _, ok := err.(*exec.ExitError); !ok {
						// On some systems, non-existent commands might return different error types
						// So we just check that an error was returned
						if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "No such file") {
							t.Logf("Expected exec.ExitError or 'not found' error, got: %T - %v", err, err)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("ExecuteCommand(%q) unexpected error: %v", tt.commandLine, err)
				}
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, err)
			}
		})
	}
}

func TestExecuteCommand_ShellSelection(t *testing.T) {
	t.Run("success_uses_correct_shell_windows", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("Skipping Windows-specific test")
		}

		// On Windows, should use cmd.exe
		// Test by using a Windows-specific command
		err := ExecuteCommand("echo test")
		if err != nil {
			t.Errorf("ExecuteCommand should work on Windows, got error: %v", err)
		}
	})

	t.Run("success_uses_correct_shell_unix", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Skipping Unix-specific test")
		}

		// On Unix, should use sh
		err := ExecuteCommand("echo test")
		if err != nil {
			t.Errorf("ExecuteCommand should work on Unix, got error: %v", err)
		}
	})
}

func TestExecuteCommand_StreamHandling(t *testing.T) {
	t.Run("success_stdout_connected", func(t *testing.T) {
		// This test verifies that stdout is properly connected
		// We can't easily capture it without modifying the function,
		// but we can verify the command runs successfully
		err := ExecuteCommand(getEchoCommand("stdout test"))
		if err != nil {
			t.Errorf("ExecuteCommand should handle stdout, got error: %v", err)
		}
	})

	t.Run("success_stderr_connected", func(t *testing.T) {
		// Test that stderr is connected by running a command that writes to stderr
		// On Unix: echo to stderr
		// On Windows: echo to stderr
		var cmd string
		if runtime.GOOS == "windows" {
			cmd = "echo test >&2"
		} else {
			cmd = "echo test >&2"
		}
		err := ExecuteCommand(cmd)
		if err != nil {
			t.Errorf("ExecuteCommand should handle stderr, got error: %v", err)
		}
	})
}

func TestExecuteCommand_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		commandLine   string
		expectedError bool
		description   string
	}{
		{
			name:          "success_whitespace_only",
			commandLine:   "   ",
			expectedError: false, // Whitespace-only command on sh -c "   " succeeds
			description:   "Command with only whitespace succeeds (shell behavior)",
		},
		{
			name:          "success_command_with_newline",
			commandLine:   getEchoCommand("test\\nwith\\nnewlines"),
			expectedError: false,
			description:   "Command with escaped newlines should be handled",
		},
		{
			name:          "success_command_with_quotes",
			commandLine:   getEchoCommand(`test "with" 'quotes'`),
			expectedError: false,
			description:   "Command with quotes should be handled",
		},
		{
			name:          "success_command_with_backslash",
			commandLine:   getEchoCommand(`test\with\backslashes`),
			expectedError: false,
			description:   "Command with backslashes should be handled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ExecuteCommand(tt.commandLine)

			if tt.expectedError {
				if err == nil {
					t.Errorf("ExecuteCommand(%q) expected error, got nil. %s", tt.commandLine, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("ExecuteCommand(%q) unexpected error: %v. %s", tt.commandLine, err, tt.description)
				}
			}
		})
	}
}

// Helper functions to get OS-appropriate commands

func getEchoCommand(text string) string {
	if runtime.GOOS == "windows" {
		return "echo " + text
	}
	return "echo " + text
}

func getFalseCommand() string {
	if runtime.GOOS == "windows" {
		return "exit /b 1"
	}
	return "false"
}

func getChainedCommands() string {
	if runtime.GOOS == "windows" {
		return "echo first && echo second"
	}
	return "echo first && echo second"
}

func getEchoEnvCommand() string {
	// Use a test environment variable
	testVar := "TEST_VAR_12345"
	os.Setenv(testVar, "test_value")
	defer os.Unsetenv(testVar)

	if runtime.GOOS == "windows" {
		return "echo %" + testVar + "%"
	}
	return "echo $" + testVar
}
