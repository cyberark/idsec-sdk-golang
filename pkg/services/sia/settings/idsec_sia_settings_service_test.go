package settings

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
)

// Sample JSON responses for testing
const (
	SettingsResponseJSON = `{
		"adb_mfa_caching": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 300,
			"client_ip_enforced": false
		},
		"certificate_validation": {
			"enabled": true
		},
		"k8s_mfa_caching": {
			"key_expiration_time_sec": 600,
			"client_ip_enforced": true
		},
		"mfa_caching": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 900
		},
		"logon_sequence": {
			"always_use_sia": true,
			"logon_sequence": "sequence1"
		}
	}`

	SettingResponseJSON = `{
		"feature_conf": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 300,
			"client_ip_enforced": false
		}
	}`

	SettingResponseNoFeatureConfJSON = `{
		"other_field": "value"
	}`

	ADBMfaCachingJSON = `{
		"feature_conf": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 300,
			"client_ip_enforced": false
		}
	}`

	CertificateValidationJSON = `{
		"feature_conf": {
			"enabled": true
		}
	}`

	K8SMfaCachingJSON = `{
		"feature_conf": {
			"key_expiration_time_sec": 600,
			"client_ip_enforced": true
		}
	}`

	SSHMfaCachingJSON = `{
		"feature_conf": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 900
		}
	}`

	LogonSequenceJSON = `{
		"feature_conf": {
			"always_use_sia": true,
			"logon_sequence": "sequence1"
		}
	}`

	RDPFileTransferJSON = `{
		"feature_conf": {
			"enabled": true
		}
	}`

	RDPKeyboardLayoutJSON = `{
		"feature_conf": {
			"layout": "en-US"
		}
	}`

	RDPMfaCachingJSON = `{
		"feature_conf": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 1200,
			"client_ip_enforced": true
		}
	}`

	RDPTokenMfaCachingJSON = `{
		"feature_conf": {
			"is_mfa_caching_enabled": true,
			"key_expiration_time_sec": 1800
		}
	}`

	RDPRecordingJSON = `{
		"feature_conf": {
			"enabled": true,
			"record_audio": false
		}
	}`

	SSHCommandAuditJSON = `{
		"feature_conf": {
			"is_command_parsing_for_audit_enabled": true,
			"shell_prompt_for_audit": "$ "
		}
	}`

	StandingAccessJSON = `{
		"feature_conf": {
			"standing_access_available": true,
			"session_max_duration": 3600,
			"session_idle_time": 900,
			"fingerprint_validation": true,
			"ssh_standing_access_available": true,
			"rdp_standing_access_available": true,
			"adb_standing_access_available": false
		}
	}`

	SelfHostedPAMJSON = `{
		"feature_conf": {
			"connector_pool_id": "pool-123",
			"is_ip_based_lb_enabled": true,
			"pvwa_base_url": "https://pvwa.example.com",
			"service_user_secret_id": "secret-456",
			"tenant_type": "production"
		}
	}`

	RDPKerberosAuthModeJSON = `{
		"feature_conf": {
			"auth_mode": "DO_NOT_USE"
		}
	}`

	RDPTranscriptionJSON = `{
		"feature_conf": {
			"enabled": true
		}
	}`

	SSHRecordingJSON = `{
		"feature_conf": {
			"enabled": true
		}
	}`

	EmptyResponseJSON = `{}`
)

// MockHTTPResponse creates a mock HTTP response with the given status code and body.
func MockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// MockGetFunc creates a mock function for GET operations that returns the provided response.
func MockGetFunc(response *http.Response, err error) func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
		return response, err
	}
}

// MockPutFunc creates a mock function for PUT operations that returns the provided response.
func MockPutFunc(response *http.Response, err error) func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		return response, err
	}
}

// MockPatchFunc creates a mock function for PATCH operations that returns the provided response.
func MockPatchFunc(response *http.Response, err error) func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		return response, err
	}
}

func MockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata: map[string]interface{}{
					"env": "dev",
				},
			},
		},
	}
}

func TestSettings(t *testing.T) {
	tests := []struct {
		name             string
		mockResponse     *http.Response
		mockError        error
		expectedSettings *settingsmodels.IdsecSIASettings
		expectedError    bool
	}{
		{
			name:         "success_with_all_settings",
			mockResponse: MockHTTPResponse(http.StatusOK, SettingsResponseJSON),
			mockError:    nil,
			expectedSettings: &settingsmodels.IdsecSIASettings{
				AdbMfaCaching: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
					IsMfaCachingEnabled:  common.Ptr(true),
					KeyExpirationTimeSec: common.Ptr(300),
					ClientIPEnforced:     common.Ptr(false),
				},
				CertificateValidation: &settingsmodels.IdsecSIASettingsCertificateValidation{
					Enabled: common.Ptr(true),
				},
				K8sMfaCaching: &settingsmodels.IdsecSIASettingsK8sMfaCaching{
					KeyExpirationTimeSec: common.Ptr(600),
					ClientIPEnforced:     common.Ptr(true),
				},
				SshMfaCaching: &settingsmodels.IdsecSIASettingsSshMfaCaching{
					IsMfaCachingEnabled:  common.Ptr(true),
					KeyExpirationTimeSec: common.Ptr(900),
				},
				LogonSequence: &settingsmodels.IdsecSIASettingsLogonSequence{
					AlwaysUseSia:  common.Ptr(true),
					LogonSequence: common.Ptr("sequence1"),
				},
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			mockResponse:  MockHTTPResponse(http.StatusInternalServerError, `{"error":"internal error"}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_invalid_json",
			mockResponse:  MockHTTPResponse(http.StatusOK, `{invalid json}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:             "success_empty_settings",
			mockResponse:     MockHTTPResponse(http.StatusOK, EmptyResponseJSON),
			mockError:        nil,
			expectedSettings: &settingsmodels.IdsecSIASettings{},
			expectedError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.ListSettings()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedSettings) {
				t.Errorf("Expected settings %+v, got %+v", tt.expectedSettings, result)
			}
		})
	}
}

func TestSetSettings(t *testing.T) {
	tests := []struct {
		name          string
		settings      *settingsmodels.IdsecSIASettings
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_settings",
			settings: &settingsmodels.IdsecSIASettings{
				AdbMfaCaching: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
					IsMfaCachingEnabled:  common.Ptr(true),
					KeyExpirationTimeSec: common.Ptr(300),
				},
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingsResponseJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			settings:      &settingsmodels.IdsecSIASettings{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			settings:      &settingsmodels.IdsecSIASettings{},
			mockResponse:  MockHTTPResponse(http.StatusBadRequest, `{"error":"bad request"}`),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPatch = MockPatchFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetSettings(tt.settings)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestAdbMfaCaching(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsAdbMfaCaching
		expectedError  bool
	}{
		{
			name:         "success_get_adb_mfa_caching",
			mockResponse: MockHTTPResponse(http.StatusOK, ADBMfaCachingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(300),
				ClientIPEnforced:     common.Ptr(false),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_no_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.AdbMfaCaching()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetAdbMfaCaching(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsAdbMfaCaching
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_adb_mfa_caching",
			setting: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(300),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, ADBMfaCachingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsAdbMfaCaching{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetAdbMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestCertificateValidation(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsCertificateValidation
		expectedError  bool
	}{
		{
			name:         "success_get_certificate_validation",
			mockResponse: MockHTTPResponse(http.StatusOK, CertificateValidationJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsCertificateValidation{
				Enabled: common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.CertificateValidation()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetCertificateValidation(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsCertificateValidation
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_certificate_validation",
			setting: &settingsmodels.IdsecSIASettingsCertificateValidation{
				Enabled: common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, CertificateValidationJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsCertificateValidation{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetCertificateValidation(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestK8SMfaCaching(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsK8sMfaCaching
		expectedError  bool
	}{
		{
			name:         "success_get_k8s_mfa_caching",
			mockResponse: MockHTTPResponse(http.StatusOK, K8SMfaCachingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsK8sMfaCaching{
				KeyExpirationTimeSec: common.Ptr(600),
				ClientIPEnforced:     common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.K8sMfaCaching()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetK8SMfaCaching(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsK8sMfaCaching
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_k8s_mfa_caching",
			setting: &settingsmodels.IdsecSIASettingsK8sMfaCaching{
				KeyExpirationTimeSec: common.Ptr(600),
				ClientIPEnforced:     common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, K8SMfaCachingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsK8sMfaCaching{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetK8sMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestSSHMfaCaching(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsSshMfaCaching
		expectedError  bool
	}{
		{
			name:         "success_get_ssh_mfa_caching",
			mockResponse: MockHTTPResponse(http.StatusOK, SSHMfaCachingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsSshMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(900),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.SshMfaCaching()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetSSHMfaCaching(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsSshMfaCaching
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_ssh_mfa_caching",
			setting: &settingsmodels.IdsecSIASettingsSshMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(900),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, SSHMfaCachingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsSshMfaCaching{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetSshMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestLogonSequence(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsLogonSequence
		expectedError  bool
	}{
		{
			name:         "success_get_logon_sequence",
			mockResponse: MockHTTPResponse(http.StatusOK, LogonSequenceJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsLogonSequence{
				AlwaysUseSia:  common.Ptr(true),
				LogonSequence: common.Ptr("sequence1"),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.LogonSequence()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetLogonSequence(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsLogonSequence
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_logon_sequence",
			setting: &settingsmodels.IdsecSIASettingsLogonSequence{
				AlwaysUseSia:  common.Ptr(true),
				LogonSequence: common.Ptr("sequence1"),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, LogonSequenceJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsLogonSequence{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetLogonSequence(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPFileTransfer(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpFileTransfer
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_file_transfer",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPFileTransferJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpFileTransfer{
				Enabled: common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_no_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpFileTransfer()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPFileTransfer(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpFileTransfer
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_file_transfer",
			setting: &settingsmodels.IdsecSIASettingsRdpFileTransfer{
				Enabled: common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPFileTransferJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsRdpFileTransfer{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			setting:       &settingsmodels.IdsecSIASettingsRdpFileTransfer{},
			mockResponse:  MockHTTPResponse(http.StatusBadRequest, `{"error":"bad request"}`),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpFileTransfer(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPKeyboardLayout(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpKeyboardLayout
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_keyboard_layout",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPKeyboardLayoutJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpKeyboardLayout{
				Layout: common.Ptr("en-US"),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_no_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpKeyboardLayout()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPKeyboardLayout(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpKeyboardLayout
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_keyboard_layout",
			setting: &settingsmodels.IdsecSIASettingsRdpKeyboardLayout{
				Layout: common.Ptr("en-US"),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPKeyboardLayoutJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsRdpKeyboardLayout{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRDPKeyboardLayout(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPMfaCaching(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpMfaCaching
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_mfa_caching",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPMfaCachingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(1200),
				ClientIPEnforced:     common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpMfaCaching()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPMfaCaching(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpMfaCaching
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_mfa_caching",
			setting: &settingsmodels.IdsecSIASettingsRdpMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(1200),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPMfaCachingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsRdpMfaCaching{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPTokenMfaCaching(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpTokenMfaCaching
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_token_mfa_caching",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPTokenMfaCachingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpTokenMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(1800),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RDPTokenMfaCaching()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPTokenMfaCaching(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpTokenMfaCaching
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_token_mfa_caching",
			setting: &settingsmodels.IdsecSIASettingsRdpTokenMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(1800),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPTokenMfaCachingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsRdpTokenMfaCaching{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpTokenMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPRecording(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpRecording
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_recording",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPRecordingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpRecording{
				Enabled: common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpRecording()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPRecording(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpRecording
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_recording",
			setting: &settingsmodels.IdsecSIASettingsRdpRecording{
				Enabled: common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPRecordingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsRdpRecording{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpRecording(tt.setting)
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestSSHCommandAudit(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsSshCommandAudit
		expectedError  bool
	}{
		{
			name:         "success_get_ssh_command_audit",
			mockResponse: MockHTTPResponse(http.StatusOK, SSHCommandAuditJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsSshCommandAudit{
				IsCommandParsingForAuditEnabled: common.Ptr(true),
				ShellPromptForAudit:             common.Ptr("$ "),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.SshCommandAudit()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetSSHCommandAudit(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsSshCommandAudit
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_ssh_command_audit",
			setting: &settingsmodels.IdsecSIASettingsSshCommandAudit{
				IsCommandParsingForAuditEnabled: common.Ptr(true),
				ShellPromptForAudit:             common.Ptr("$ "),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, SSHCommandAuditJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsSshCommandAudit{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetSshCommandAudit(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestStandingAccess(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsStandingAccess
		expectedError  bool
	}{
		{
			name:         "success_get_standing_access",
			mockResponse: MockHTTPResponse(http.StatusOK, StandingAccessJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsStandingAccess{
				StandingAccessAvailable:    common.Ptr(true),
				SessionMaxDuration:         common.Ptr(3600),
				SessionIdleTime:            common.Ptr(900),
				FingerprintValidation:      common.Ptr(true),
				SSHStandingAccessAvailable: common.Ptr(true),
				RDPStandingAccessAvailable: common.Ptr(true),
				ADBStandingAccessAvailable: common.Ptr(false),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.StandingAccess()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetStandingAccess(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsStandingAccess
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_standing_access",
			setting: &settingsmodels.IdsecSIASettingsStandingAccess{
				StandingAccessAvailable:    common.Ptr(true),
				SessionMaxDuration:         common.Ptr(3600),
				SessionIdleTime:            common.Ptr(900),
				FingerprintValidation:      common.Ptr(true),
				SSHStandingAccessAvailable: common.Ptr(true),
				RDPStandingAccessAvailable: common.Ptr(true),
				ADBStandingAccessAvailable: common.Ptr(false),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, StandingAccessJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsStandingAccess{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetStandingAccess(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestSelfHostedPAM(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsSelfHostedPam
		expectedError  bool
	}{
		{
			name:         "success_get_self_hosted_pam",
			mockResponse: MockHTTPResponse(http.StatusOK, SelfHostedPAMJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsSelfHostedPam{
				ConnectorPoolID:     common.Ptr("pool-123"),
				IsIPBasedLBEnabled:  common.Ptr(true),
				PVWABaseURL:         common.Ptr("https://pvwa.example.com"),
				ServiceUserSecretID: common.Ptr("secret-456"),
				TenantType:          common.Ptr("production"),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.SelfHostedPam()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetSelfHostedPAM(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsSelfHostedPam
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_self_hosted_pam",
			setting: &settingsmodels.IdsecSIASettingsSelfHostedPam{
				ConnectorPoolID:     common.Ptr("pool-123"),
				IsIPBasedLBEnabled:  common.Ptr(true),
				PVWABaseURL:         common.Ptr("https://pvwa.example.com"),
				ServiceUserSecretID: common.Ptr("secret-456"),
				TenantType:          common.Ptr("production"),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, SelfHostedPAMJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			setting:       &settingsmodels.IdsecSIASettingsSelfHostedPam{},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetSelfHostedPam(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPKerberosAuthMode(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpKerberosAuthMode
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_kerberos_auth_mode",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPKerberosAuthModeJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{
				AuthMode: common.Ptr("DO_NOT_USE"),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			mockResponse:  MockHTTPResponse(http.StatusInternalServerError, `{"error":"internal error"}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_invalid_json",
			mockResponse:  MockHTTPResponse(http.StatusOK, `{invalid json}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_missing_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpKerberosAuthMode()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPKerberosAuthMode(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpKerberosAuthMode
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_kerberos_auth_mode",
			setting: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{
				AuthMode: common.Ptr("DO_NOT_USE"),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPKerberosAuthModeJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			setting: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{
				AuthMode: common.Ptr("USE_KERBEROS"),
			},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name: "error_non_200_status",
			setting: &settingsmodels.IdsecSIASettingsRdpKerberosAuthMode{
				AuthMode: common.Ptr("USE_KERBEROS"),
			},
			mockResponse:  MockHTTPResponse(http.StatusBadRequest, `{"error":"bad request"}`),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpKerberosAuthMode(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestRDPTranscription(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsRdpTranscription
		expectedError  bool
	}{
		{
			name:         "success_get_rdp_transcription",
			mockResponse: MockHTTPResponse(http.StatusOK, RDPTranscriptionJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsRdpTranscription{
				Enabled: common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			mockResponse:  MockHTTPResponse(http.StatusInternalServerError, `{"error":"internal error"}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_invalid_json",
			mockResponse:  MockHTTPResponse(http.StatusOK, `{invalid json}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_missing_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.RdpTranscription()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetRDPTranscription(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsRdpTranscription
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_rdp_transcription",
			setting: &settingsmodels.IdsecSIASettingsRdpTranscription{
				Enabled: common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, RDPTranscriptionJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			setting: &settingsmodels.IdsecSIASettingsRdpTranscription{
				Enabled: common.Ptr(false),
			},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name: "error_non_200_status",
			setting: &settingsmodels.IdsecSIASettingsRdpTranscription{
				Enabled: common.Ptr(false),
			},
			mockResponse:  MockHTTPResponse(http.StatusBadRequest, `{"error":"bad request"}`),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetRdpTranscription(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestSSHRecording(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *http.Response
		mockError      error
		expectedResult *settingsmodels.IdsecSIASettingsSshRecording
		expectedError  bool
	}{
		{
			name:         "success_get_ssh_recording",
			mockResponse: MockHTTPResponse(http.StatusOK, SSHRecordingJSON),
			mockError:    nil,
			expectedResult: &settingsmodels.IdsecSIASettingsSshRecording{
				Enabled: common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name:          "error_http_request_failed",
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name:          "error_non_200_status",
			mockResponse:  MockHTTPResponse(http.StatusInternalServerError, `{"error":"internal error"}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_invalid_json",
			mockResponse:  MockHTTPResponse(http.StatusOK, `{invalid json}`),
			mockError:     nil,
			expectedError: true,
		},
		{
			name:          "error_missing_feature_conf",
			mockResponse:  MockHTTPResponse(http.StatusOK, SettingResponseNoFeatureConfJSON),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			result, err := service.SshRecording()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetSSHRecording(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsSshRecording
		mockResponse  *http.Response
		mockError     error
		expectedError bool
	}{
		{
			name: "success_set_ssh_recording",
			setting: &settingsmodels.IdsecSIASettingsSshRecording{
				Enabled: common.Ptr(true),
			},
			mockResponse:  MockHTTPResponse(http.StatusOK, SSHRecordingJSON),
			mockError:     nil,
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			setting: &settingsmodels.IdsecSIASettingsSshRecording{
				Enabled: common.Ptr(false),
			},
			mockResponse:  nil,
			mockError:     errors.New("network error"),
			expectedError: true,
		},
		{
			name: "error_non_200_status",
			setting: &settingsmodels.IdsecSIASettingsSshRecording{
				Enabled: common.Ptr(false),
			},
			mockResponse:  MockHTTPResponse(http.StatusBadRequest, `{"error":"bad request"}`),
			mockError:     nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockResponse, tt.mockError)
			service.doGet = MockGetFunc(tt.mockResponse, tt.mockError)
			_, err = service.SetSshRecording(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

// Partial setting tests - testing when only one field is set but backend returns all fields
func TestSetAdbMfaCaching_PartialSetting(t *testing.T) {
	const partialSetResponseJSON = `{
  "feature_conf": {
   "is_mfa_caching_enabled": true,
   "key_expiration_time_sec": 600,
   "client_ip_enforced": true
  }
 }`

	tests := []struct {
		name           string
		setting        *settingsmodels.IdsecSIASettingsAdbMfaCaching
		mockPutResp    *http.Response
		mockGetResp    *http.Response
		expectedResult *settingsmodels.IdsecSIASettingsAdbMfaCaching
		expectedError  bool
	}{
		{
			name: "success_partial_set_only_enabled_field",
			setting: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				IsMfaCachingEnabled: common.Ptr(true),
			},
			mockPutResp: MockHTTPResponse(http.StatusOK, "{}"),
			mockGetResp: MockHTTPResponse(http.StatusOK, partialSetResponseJSON),
			expectedResult: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(600),
				ClientIPEnforced:     common.Ptr(true),
			},
			expectedError: false,
		},
		{
			name: "success_partial_set_only_expiration_field",
			setting: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				KeyExpirationTimeSec: common.Ptr(900),
			},
			mockPutResp: MockHTTPResponse(http.StatusOK, "{}"),
			mockGetResp: MockHTTPResponse(http.StatusOK, partialSetResponseJSON),
			expectedResult: &settingsmodels.IdsecSIASettingsAdbMfaCaching{
				IsMfaCachingEnabled:  common.Ptr(true),
				KeyExpirationTimeSec: common.Ptr(600),
				ClientIPEnforced:     common.Ptr(true),
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockPutResp, nil)
			service.doGet = MockGetFunc(tt.mockGetResp, nil)
			result, err := service.SetAdbMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetK8SMfaCaching_PartialSetting(t *testing.T) {
	const partialSetResponseJSON = `{
  "feature_conf": {
   "key_expiration_time_sec": 1200,
   "client_ip_enforced": false
  }
 }`

	tests := []struct {
		name           string
		setting        *settingsmodels.IdsecSIASettingsK8sMfaCaching
		mockPutResp    *http.Response
		mockGetResp    *http.Response
		expectedResult *settingsmodels.IdsecSIASettingsK8sMfaCaching
		expectedError  bool
	}{
		{
			name: "success_partial_set_only_expiration_field",
			setting: &settingsmodels.IdsecSIASettingsK8sMfaCaching{
				KeyExpirationTimeSec: common.Ptr(900),
			},
			mockPutResp: MockHTTPResponse(http.StatusOK, "{}"),
			mockGetResp: MockHTTPResponse(http.StatusOK, partialSetResponseJSON),
			expectedResult: &settingsmodels.IdsecSIASettingsK8sMfaCaching{
				KeyExpirationTimeSec: common.Ptr(1200),
				ClientIPEnforced:     common.Ptr(false),
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}
			service.doPut = MockPutFunc(tt.mockPutResp, nil)
			service.doGet = MockGetFunc(tt.mockGetResp, nil)
			result, err := service.SetK8sMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

// Empty setting tests
func TestSetAdbMfaCaching_EmptySetting(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsAdbMfaCaching
		expectedError bool
	}{
		{
			name:          "success_empty_setting_returns_nil",
			setting:       &settingsmodels.IdsecSIASettingsAdbMfaCaching{},
			expectedError: false,
		},
		{
			name:          "success_nil_setting_returns_nil",
			setting:       nil,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}

			// For empty/nil settings, the function should return early without making any HTTP calls
			// We don't need to mock anything as no calls should be made
			service.doPut = MockPutFunc(nil, errors.New("should not be called"))
			service.doGet = MockGetFunc(MockHTTPResponse(http.StatusOK, ADBMfaCachingJSON), nil)

			result, err := service.SetAdbMfaCaching(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Result should be the current setting from the get operation
			if result == nil {
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestSetCertificateValidation_EmptySetting(t *testing.T) {
	tests := []struct {
		name          string
		setting       *settingsmodels.IdsecSIASettingsCertificateValidation
		expectedError bool
	}{
		{
			name:          "success_empty_setting_returns_nil",
			setting:       &settingsmodels.IdsecSIASettingsCertificateValidation{},
			expectedError: false,
		},
		{
			name:          "success_nil_setting_returns_nil",
			setting:       nil,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecSIASettingsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecSIASettingsService: %v", err)
			}

			service.doPut = MockPutFunc(nil, errors.New("should not be called"))
			service.doGet = MockGetFunc(MockHTTPResponse(http.StatusOK, CertificateValidationJSON), nil)

			result, err := service.SetCertificateValidation(tt.setting)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected result, got nil")
			}
		})
	}
}
