package sshca

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections"
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sshcamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca/models"
)

// MockHTTPClient is a mock implementation of HTTP client for testing.
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return &http.Response{StatusCode: http.StatusOK}, nil
}

// MockSSHConnection is a mock implementation of IdsecConnection for testing SSH operations.
type MockSSHConnection struct {
	ConnectFunc           func(details *connectionsmodels.IdsecConnectionDetails) error
	DisconnectFunc        func() error
	RunCommandFunc        func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error)
	SuspendConnectionFunc func() error
	RestoreConnectionFunc func() error
	IsSuspendedFunc       func() bool
	IsConnectedFunc       func() bool
}

func (m *MockSSHConnection) Connect(details *connectionsmodels.IdsecConnectionDetails) error {
	if m.ConnectFunc != nil {
		return m.ConnectFunc(details)
	}
	return nil
}

func (m *MockSSHConnection) Disconnect() error {
	if m.DisconnectFunc != nil {
		return m.DisconnectFunc()
	}
	return nil
}

func (m *MockSSHConnection) RunCommand(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
	if m.RunCommandFunc != nil {
		return m.RunCommandFunc(cmd)
	}
	return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
}

func (m *MockSSHConnection) SuspendConnection() error {
	if m.SuspendConnectionFunc != nil {
		return m.SuspendConnectionFunc()
	}
	return nil
}

func (m *MockSSHConnection) RestoreConnection() error {
	if m.RestoreConnectionFunc != nil {
		return m.RestoreConnectionFunc()
	}
	return nil
}

func (m *MockSSHConnection) IsSuspended() bool {
	if m.IsSuspendedFunc != nil {
		return m.IsSuspendedFunc()
	}
	return false
}

func (m *MockSSHConnection) ConnectionDetails() *connectionsmodels.IdsecConnectionDetails {
	return nil
}

func (m *MockSSHConnection) IsConnected() bool {
	if m.IsConnectedFunc != nil {
		return m.IsConnectedFunc()
	}
	return true
}

// NewMockResponse creates a mock HTTP response for testing.
func NewMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// NewMockContext creates a mock context for testing.
func NewMockContext() context.Context {
	return context.Background()
}

// createTestService creates a properly initialized test service with mocked dependencies.
func createTestService() *IdsecSIASSHCAService {
	service := &IdsecSIASSHCAService{}
	service.IdsecBaseService = &services.IdsecBaseService{
		Logger: common.GetLogger("test", common.Unknown),
	}
	return service
}

// TestGenerateNewCA tests the GenerateNewCA method.
//
// This test validates the ability to generate a new CA key version through the API.
// It tests both successful generation and various error conditions.
func TestGenerateNewCA(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_ca_generated",
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:             "error_bad_request",
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid request"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to generate new CA key",
		},
		{
			name:             "error_unauthorized",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to generate new CA key",
		},
		{
			name:             "error_internal_server",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to generate new CA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.GenerateNewCA()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestDeactivatePreviousCa tests the DeactivatePreviousCa method.
//
// This test validates the ability to deactivate the previous CA key version.
// It covers success cases and various HTTP error responses.
func TestDeactivatePreviousCa(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_ca_deactivated",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:             "error_not_found",
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "CA not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate previous CA key",
		},
		{
			name:             "error_forbidden",
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate previous CA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.DeactivatePreviousCa()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestReactivatePreviousCa tests the ReactivatePreviousCa method.
//
// This test validates the ability to reactivate the previous CA key version.
// It tests successful reactivation and error scenarios.
func TestReactivatePreviousCa(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_ca_reactivated",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:             "error_conflict",
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "already active"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to reactivate previous CA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.ReactivatePreviousCa()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestPublicKey tests the PublicKey method.
//
// This test validates retrieval of the SSH CA public key.
// It tests successful retrieval, file output, and error handling.
func TestPublicKey(t *testing.T) {
	testPublicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test-key"

	tests := []struct {
		name             string
		getPublicKey     *sshcamodels.IdsecSIAGetSSHPublicKey
		mockStatusCode   int
		mockBody         string
		expectedResult   string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, outputFile string)
	}{
		{
			name:           "success_get_public_key",
			getPublicKey:   nil,
			mockStatusCode: http.StatusOK,
			mockBody:       testPublicKey,
			expectedResult: testPublicKey,
			expectedError:  false,
		},
		{
			name: "success_with_output_file",
			getPublicKey: &sshcamodels.IdsecSIAGetSSHPublicKey{
				OutputFile: filepath.Join(t.TempDir(), "public_key.pub"),
			},
			mockStatusCode: http.StatusOK,
			mockBody:       testPublicKey,
			expectedResult: testPublicKey,
			expectedError:  false,
			validateFunc: func(t *testing.T, outputFile string) {
				content, err := os.ReadFile(outputFile)
				if err != nil {
					t.Errorf("Failed to read output file: %v", err)
					return
				}
				if string(content) != testPublicKey {
					t.Errorf("Expected file content '%s', got '%s'", testPublicKey, string(content))
				}
			},
		},
		{
			name:             "error_not_found",
			getPublicKey:     nil,
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get public key",
		},
		{
			name:             "error_unauthorized",
			getPublicKey:     nil,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.PublicKey(tt.getPublicKey)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if result != tt.expectedResult {
					t.Errorf("Expected result '%s', got '%s'", tt.expectedResult, result)
				}
				if tt.validateFunc != nil && tt.getPublicKey != nil {
					tt.validateFunc(t, tt.getPublicKey.OutputFile)
				}
			}
		})
	}
}

// TestPublicKeyScript tests the PublicKeyScript method.
//
// This test validates retrieval of the public key installation script.
// It tests different shell types, file output, and error conditions.
func TestPublicKeyScript(t *testing.T) {
	testScript := "#!/bin/bash\necho 'test script'"
	testScriptB64 := base64.StdEncoding.EncodeToString([]byte(testScript))

	tests := []struct {
		name               string
		getPublicKeyScript *sshcamodels.IdsecSIAGetSSHPublicKeyScript
		mockStatusCode     int
		mockBody           string
		expectedResult     string
		expectedError      bool
		expectedErrorMsg   string
		validateFunc       func(t *testing.T, outputFile string)
	}{
		{
			name:               "success_default_shell",
			getPublicKeyScript: nil,
			mockStatusCode:     http.StatusOK,
			mockBody:           fmt.Sprintf(`{"base64_cmd": "%s"}`, testScriptB64),
			expectedResult:     testScript,
			expectedError:      false,
		},
		{
			name: "success_bash_shell",
			getPublicKeyScript: &sshcamodels.IdsecSIAGetSSHPublicKeyScript{
				Shell: "bash",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       fmt.Sprintf(`{"base64_cmd": "%s"}`, testScriptB64),
			expectedResult: testScript,
			expectedError:  false,
		},
		{
			name: "success_korn_shell",
			getPublicKeyScript: &sshcamodels.IdsecSIAGetSSHPublicKeyScript{
				Shell: "kornShell",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       fmt.Sprintf(`{"base64_cmd": "%s"}`, testScriptB64),
			expectedResult: testScript,
			expectedError:  false,
		},
		{
			name: "success_with_output_file",
			getPublicKeyScript: &sshcamodels.IdsecSIAGetSSHPublicKeyScript{
				OutputFile: filepath.Join(t.TempDir(), "script.sh"),
			},
			mockStatusCode: http.StatusOK,
			mockBody:       fmt.Sprintf(`{"base64_cmd": "%s"}`, testScriptB64),
			expectedResult: testScript,
			expectedError:  false,
			validateFunc: func(t *testing.T, outputFile string) {
				content, err := os.ReadFile(outputFile)
				if err != nil {
					t.Errorf("Failed to read output file: %v", err)
					return
				}
				if string(content) != testScript {
					t.Errorf("Expected file content '%s', got '%s'", testScript, string(content))
				}
			},
		},
		{
			name:               "error_invalid_json",
			getPublicKeyScript: nil,
			mockStatusCode:     http.StatusOK,
			mockBody:           `invalid json`,
			expectedError:      true,
		},
		{
			name:               "error_missing_base64_cmd",
			getPublicKeyScript: nil,
			mockStatusCode:     http.StatusOK,
			mockBody:           `{"other_field": "value"}`,
			expectedError:      true,
			expectedErrorMsg:   "failed to parse public key script response",
		},
		{
			name:               "error_invalid_base64",
			getPublicKeyScript: nil,
			mockStatusCode:     http.StatusOK,
			mockBody:           `{"base64_cmd": "invalid base64!!!"}`,
			expectedError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.PublicKeyScript(tt.getPublicKeyScript)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if result != tt.expectedResult {
					t.Errorf("Expected result '%s', got '%s'", tt.expectedResult, result)
				}
				if tt.validateFunc != nil && tt.getPublicKeyScript != nil {
					tt.validateFunc(t, tt.getPublicKeyScript.OutputFile)
				}
			}
		})
	}
}

// TestInstallPublicKey tests the InstallPublicKey method.
//
// This test validates the installation of SSH CA public key on target machines.
// It tests connection establishment, pre-installation checks, and the installation process.
func TestInstallPublicKey(t *testing.T) {
	testScript := "#!/bin/bash\necho 'install script'"

	tests := []struct {
		name             string
		installPublicKey *sshcamodels.IdsecSIAInstallSSHPublicKey
		mockConnection   *MockSSHConnection
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "success_install_on_new_machine",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "password",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				ConnectFunc: func(details *connectionsmodels.IdsecConnectionDetails) error {
					return nil
				},
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					// First call is check script (not installed), second is install
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 2}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_already_installed",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "password",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_replace_different_ca",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "password",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 3}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_korn_shell",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "kornShell",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 2}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "error_connection_failed",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "wrong",
			},
			mockConnection: &MockSSHConnection{
				ConnectFunc: func(details *connectionsmodels.IdsecConnectionDetails) error {
					return fmt.Errorf("authentication failed")
				},
			},
			expectedError:    true,
			expectedErrorMsg: "failed to connect",
		},
		{
			name: "error_check_script_failed",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return nil, fmt.Errorf("connection lost")
				},
			},
			expectedError:    true,
			expectedErrorMsg: "failed to run installation check command",
		},
		{
			name: "error_installation_failed",
			installPublicKey: &sshcamodels.IdsecSIAInstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 2}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{
						RC:     1,
						Stderr: "permission denied",
						Stdout: "",
					}, nil
				},
			},
			expectedError:    true,
			expectedErrorMsg: "failed to install public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				scriptB64 := base64.StdEncoding.EncodeToString([]byte(testScript))
				mockBody := fmt.Sprintf(`{"base64_cmd": "%s"}`, scriptB64)
				return NewMockResponse(http.StatusOK, mockBody), nil
			}
			service.newConnection = func() connections.IdsecConnection {
				return tt.mockConnection
			}

			_, err := service.InstallPublicKey(tt.installPublicKey)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestUninstallPublicKey tests the UninstallPublicKey method.
//
// This test validates the uninstallation of SSH CA public key from target machines.
// It tests pre-uninstall checks and the uninstallation process.
func TestUninstallPublicKey(t *testing.T) {
	testPublicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test-key"

	tests := []struct {
		name               string
		uninstallPublicKey *sshcamodels.IdsecSIAUninstallSSHPublicKey
		mockConnection     *MockSSHConnection
		expectedError      bool
		expectedErrorMsg   string
	}{
		{
			name: "success_uninstall_installed_ca",
			uninstallPublicKey: &sshcamodels.IdsecSIAUninstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "password",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_not_installed",
			uninstallPublicKey: &sshcamodels.IdsecSIAUninstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 2}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_misconfigured_uninstall_anyway",
			uninstallPublicKey: &sshcamodels.IdsecSIAUninstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 1}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "success_korn_shell",
			uninstallPublicKey: &sshcamodels.IdsecSIAUninstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "kornShell",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedError: false,
		},
		{
			name: "error_uninstall_failed",
			uninstallPublicKey: &sshcamodels.IdsecSIAUninstallSSHPublicKey{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					if cmd.IgnoreRC {
						return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
					}
					return &connectionsmodels.IdsecConnectionResult{
						RC:     1,
						Stderr: "failed to restart sshd",
					}, nil
				},
			},
			expectedError:    true,
			expectedErrorMsg: "failed to uninstall public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, testPublicKey), nil
			}
			service.newConnection = func() connections.IdsecConnection {
				return tt.mockConnection
			}

			_, err := service.UninstallPublicKey(tt.uninstallPublicKey)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestIsPublicKeyInstalled tests the IsPublicKeyInstalled method.
//
// This test validates the ability to check if the SSH CA public key is installed.
// It tests various installation states and error conditions.
func TestIsPublicKeyInstalled(t *testing.T) {
	testPublicKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test-key"

	tests := []struct {
		name                 string
		isPublicKeyInstalled *sshcamodels.IdsecSIAIsSSHPublicKeyInstalled
		mockConnection       *MockSSHConnection
		expectedResult       bool
		expectedError        bool
		expectedErrorMsg     string
	}{
		{
			name: "success_installed",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Password:      "password",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "success_not_installed",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 2}, nil
				},
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "success_different_ca",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "bash",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 3}, nil
				},
			},
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "success_korn_shell",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
				Shell:         "kornShell",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return &connectionsmodels.IdsecConnectionResult{RC: 0}, nil
				},
			},
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "error_connection_failed",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
			},
			mockConnection: &MockSSHConnection{
				ConnectFunc: func(details *connectionsmodels.IdsecConnectionDetails) error {
					return fmt.Errorf("connection refused")
				},
			},
			expectedResult:   false,
			expectedError:    true,
			expectedErrorMsg: "failed to connect",
		},
		{
			name: "error_check_failed",
			isPublicKeyInstalled: &sshcamodels.IdsecSIAIsSSHPublicKeyInstalled{
				TargetMachine: "192.168.1.100",
				Username:      "admin",
			},
			mockConnection: &MockSSHConnection{
				RunCommandFunc: func(cmd *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
					return nil, fmt.Errorf("command execution failed")
				},
			},
			expectedResult:   false,
			expectedError:    true,
			expectedErrorMsg: "failed to run installation check command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, testPublicKey), nil
			}
			service.newConnection = func() connections.IdsecConnection {
				return tt.mockConnection
			}

			result, err := service.IsPublicKeyInstalled(tt.isPublicKeyInstalled)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if result.Result != tt.expectedResult {
					t.Errorf("Expected result %v, got %v", tt.expectedResult, result)
				}
			}
		})
	}
}
