package winrm

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections/connectiondata"
)

func TestNewIdsecWinRMConnection(t *testing.T) {
	tests := []struct {
		name           string
		validateFunc   func(t *testing.T, result *IdsecWinRMConnection)
		expectedResult bool
	}{
		{
			name: "success_creates_new_instance",
			validateFunc: func(t *testing.T, result *IdsecWinRMConnection) {
				if result == nil {
					t.Error("Expected non-nil connection")
					return
				}
				if result.isConnected {
					t.Error("Expected isConnected to be false")
				}
				if result.isSuspended {
					t.Error("Expected isSuspended to be false")
				}
				if result.logger == nil {
					t.Error("Expected logger to be initialized")
				}
				if result.winrmClient != nil {
					t.Error("Expected winrmClient to be nil")
				}
				if result.winrmShell != nil {
					t.Error("Expected winrmShell to be nil")
				}
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := NewIdsecWinRMConnection()

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecWinRMConnection_Connect_Validation(t *testing.T) {
	// These tests validate the input validation and setup logic without external dependencies
	// Create temporary certificate file for testing
	tempCertFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer os.Remove(tempCertFile.Name())

	_, err = tempCertFile.WriteString("-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----")
	if err != nil {
		t.Fatalf("Failed to write cert data: %v", err)
	}
	tempCertFile.Close()

	tests := []struct {
		name              string
		connectionDetails *connectionsmodels.IdsecConnectionDetails
		setupFunc         func(conn *IdsecWinRMConnection)
		expectedError     bool
		expectedErrorMsg  string
		validateFunc      func(t *testing.T, conn *IdsecWinRMConnection)
	}{
		{
			name: "success_already_connected",
			connectionDetails: &connectionsmodels.IdsecConnectionDetails{
				Address: "test-server",
				Port:    5986,
				Credentials: &connectionsmodels.IdsecConnectionCredentials{
					User:     "testuser",
					Password: "testpass",
				},
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if !conn.isConnected {
					t.Error("Expected connection to remain connected")
				}
			},
		},
		{
			name: "error_missing_credentials",
			connectionDetails: &connectionsmodels.IdsecConnectionDetails{
				Address: "test-server",
				Port:    5986,
			},
			expectedError:    true,
			expectedErrorMsg: "missing credentials for WinRM connection",
		},
		{
			name: "error_invalid_certificate_path",
			connectionDetails: &connectionsmodels.IdsecConnectionDetails{
				Address: "test-server",
				Port:    5986,
				Credentials: &connectionsmodels.IdsecConnectionCredentials{
					User:     "testuser",
					Password: "testpass",
				},
				ConnectionData: &connectiondata.IdsecWinRMConnectionData{
					CertificatePath: "/nonexistent/cert.pem",
				},
			},
			expectedError:    true,
			expectedErrorMsg: "failed to read certificate file",
		},
		{
			name: "success_valid_certificate_path",
			connectionDetails: &connectionsmodels.IdsecConnectionDetails{
				Address: "test-server",
				Port:    5986,
				Credentials: &connectionsmodels.IdsecConnectionCredentials{
					User:     "testuser",
					Password: "testpass",
				},
				ConnectionData: &connectiondata.IdsecWinRMConnectionData{
					CertificatePath:  tempCertFile.Name(),
					TrustCertificate: true,
				},
			},
			// This will fail at WinRM client creation since we don't have a real server,
			// but it validates the certificate reading logic
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			err := conn.Connect(tt.connectionDetails)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, conn)
			}
		})
	}
}

func TestIdsecWinRMConnection_Disconnect(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(conn *IdsecWinRMConnection)
		expectedError bool
		validateFunc  func(t *testing.T, conn *IdsecWinRMConnection)
	}{
		{
			name: "success_not_connected",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = false
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if conn.isConnected {
					t.Error("Expected connection to remain disconnected")
				}
			},
		},
		// {
		// 	name: "success_connected_no_shell",
		// 	setupFunc: func(conn *IdsecWinRMConnection) {
		// 		conn.isConnected = true
		// 		conn.isSuspended = true
		// 		// No shell set - tests the nil check
		// 	},
		// 	expectedError: false,
		// 	validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
		// 		if conn.isConnected {
		// 			t.Error("Expected connection to be disconnected")
		// 		}
		// 		if conn.isSuspended {
		// 			t.Error("Expected suspension to be cleared")
		// 		}
		// 	},
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			err := conn.Disconnect()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, conn)
			}
		})
	}
}

func TestIdsecWinRMConnection_SuspendConnection(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(conn *IdsecWinRMConnection)
		expectedError bool
		validateFunc  func(t *testing.T, conn *IdsecWinRMConnection)
	}{
		{
			name: "success_suspend_not_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = false
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if !conn.isSuspended {
					t.Error("Expected connection to be suspended")
				}
			},
		},
		{
			name: "success_suspend_already_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = true
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if !conn.isSuspended {
					t.Error("Expected connection to remain suspended")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			err := conn.SuspendConnection()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, conn)
			}
		})
	}
}

func TestIdsecWinRMConnection_RestoreConnection(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(conn *IdsecWinRMConnection)
		expectedError bool
		validateFunc  func(t *testing.T, conn *IdsecWinRMConnection)
	}{
		{
			name: "success_restore_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = true
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if conn.isSuspended {
					t.Error("Expected connection to not be suspended")
				}
			},
		},
		{
			name: "success_restore_not_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = false
			},
			expectedError: false,
			validateFunc: func(t *testing.T, conn *IdsecWinRMConnection) {
				if conn.isSuspended {
					t.Error("Expected connection to remain not suspended")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			err := conn.RestoreConnection()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, conn)
			}
		})
	}
}

func TestIdsecWinRMConnection_IsSuspended(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(conn *IdsecWinRMConnection)
		expectedResult bool
	}{
		{
			name: "returns_true_when_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = true
			},
			expectedResult: true,
		},
		{
			name: "returns_false_when_not_suspended",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isSuspended = false
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			result := conn.IsSuspended()

			if result != tt.expectedResult {
				t.Errorf("Expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecWinRMConnection_IsConnected(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(conn *IdsecWinRMConnection)
		expectedResult bool
	}{
		{
			name: "returns_true_when_connected",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
			},
			expectedResult: true,
		},
		{
			name: "returns_false_when_not_connected",
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = false
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			result := conn.IsConnected()

			if result != tt.expectedResult {
				t.Errorf("Expected result %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecWinRMConnection_RunCommand_ValidationLogic(t *testing.T) {
	// These tests focus on the validation logic without external dependencies
	tests := []struct {
		name             string
		command          *connectionsmodels.IdsecConnectionCommand
		setupFunc        func(conn *IdsecWinRMConnection)
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "error_not_connected",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = false
			},
			expectedError:    true,
			expectedErrorMsg: "cannot run command while not being connected",
		},
		{
			name: "error_suspended",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = true
			},
			expectedError:    true,
			expectedErrorMsg: "cannot run command while not being connected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			_, err := conn.RunCommand(tt.command)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}
		})
	}
}

// Test constants
func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
	}{
		{
			name:     "winrm_https_port_correct",
			value:    WinRMHTTPSPort,
			expected: 5986,
		},
		{
			name:     "connection_timeout_correct",
			value:    winrmConnectionTimeout,
			expected: 60 * time.Second,
		},
		{
			name:     "max_single_command_size_correct",
			value:    maxSingleCommandSize,
			expected: 2000,
		},
		{
			name:     "max_chunk_size_correct",
			value:    maxChunkSize,
			expected: 4000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.value != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, tt.value)
			}
		})
	}
}

func TestIdsecWinRMConnection_RunCommand_RetryLogic(t *testing.T) {
	tests := []struct {
		name             string
		command          *connectionsmodels.IdsecConnectionCommand
		setupFunc        func(conn *IdsecWinRMConnection)
		mockRunCommand   func(attempt int) (*connectionsmodels.IdsecConnectionResult, error)
		expectedError    bool
		expectedErrorMsg string
		expectedAttempts int
		validateFunc     func(t *testing.T, result *connectionsmodels.IdsecConnectionResult, attempts int)
	}{
		{
			name: "success_first_attempt_no_retry",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 1,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				return &connectionsmodels.IdsecConnectionResult{
					Stdout: "test output",
					Stderr: "",
					RC:     0,
				}, nil
			},
			expectedError:    false,
			expectedAttempts: 1,
			validateFunc: func(t *testing.T, result *connectionsmodels.IdsecConnectionResult, attempts int) {
				if result.Stdout != "test output" {
					t.Errorf("Expected stdout 'test output', got '%s'", result.Stdout)
				}
				if attempts != 1 {
					t.Errorf("Expected 1 attempt, got %d", attempts)
				}
			},
		},
		{
			name: "success_retry_on_error_succeeds_second_attempt",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 3,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				if attempt == 1 {
					return nil, fmt.Errorf("temporary failure occurred")
				}
				return &connectionsmodels.IdsecConnectionResult{
					Stdout: "test output",
					Stderr: "",
					RC:     0,
				}, nil
			},
			expectedError:    false,
			expectedAttempts: 2,
			validateFunc: func(t *testing.T, result *connectionsmodels.IdsecConnectionResult, attempts int) {
				if result.Stdout != "test output" {
					t.Errorf("Expected stdout 'test output', got '%s'", result.Stdout)
				}
				if attempts != 2 {
					t.Errorf("Expected 2 attempts, got %d", attempts)
				}
			},
		},
		{
			name: "success_retry_succeeds_last_attempt",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 3,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				if attempt < 3 {
					return nil, fmt.Errorf("temporary failure occurred")
				}
				return &connectionsmodels.IdsecConnectionResult{
					Stdout: "test output",
					Stderr: "",
					RC:     0,
				}, nil
			},
			expectedError:    false,
			expectedAttempts: 3,
			validateFunc: func(t *testing.T, result *connectionsmodels.IdsecConnectionResult, attempts int) {
				if result.Stdout != "test output" {
					t.Errorf("Expected stdout 'test output', got '%s'", result.Stdout)
				}
				if attempts != 3 {
					t.Errorf("Expected 3 attempts, got %d", attempts)
				}
			},
		},
		{
			name: "error_retry_exhausted",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 3,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				return nil, fmt.Errorf("persistent failure")
			},
			expectedError:    true,
			expectedErrorMsg: "persistent failure",
			expectedAttempts: 3,
		},
		{
			name: "error_zero_retry_count_returns_retries_exhausted",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 0,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				return &connectionsmodels.IdsecConnectionResult{
					Stdout: "test output",
					Stderr: "",
					RC:     0,
				}, nil
			},
			expectedError:    true,
			expectedErrorMsg: "retries exhausted",
			expectedAttempts: 0,
		},
		{
			name: "success_multiple_retries_with_delay",
			command: &connectionsmodels.IdsecConnectionCommand{
				Command:    "echo test",
				ExpectedRC: 0,
				RetryCount: 4,
				RetryDelay: 0,
			},
			setupFunc: func(conn *IdsecWinRMConnection) {
				conn.isConnected = true
				conn.isSuspended = false
			},
			mockRunCommand: func(attempt int) (*connectionsmodels.IdsecConnectionResult, error) {
				if attempt <= 3 {
					return nil, fmt.Errorf("attempt %d failed", attempt)
				}
				return &connectionsmodels.IdsecConnectionResult{
					Stdout: "success after retries",
					Stderr: "",
					RC:     0,
				}, nil
			},
			expectedError:    false,
			expectedAttempts: 4,
			validateFunc: func(t *testing.T, result *connectionsmodels.IdsecConnectionResult, attempts int) {
				if result.Stdout != "success after retries" {
					t.Errorf("Expected stdout 'success after retries', got '%s'", result.Stdout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := NewIdsecWinRMConnection()
			if tt.setupFunc != nil {
				tt.setupFunc(conn)
			}

			attemptCount := 0
			conn.runCommandMock = func(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
				attemptCount++
				return tt.mockRunCommand(attemptCount)
			}

			result, err := conn.RunCommand(tt.command)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				if attemptCount != tt.expectedAttempts {
					t.Errorf("Expected %d attempts, got %d", tt.expectedAttempts, attemptCount)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result, attemptCount)
			}
		})
	}
}
