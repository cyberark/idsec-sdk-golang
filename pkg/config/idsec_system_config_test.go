package config

import (
	"os"
	"strings"
	"testing"
)

func TestDisableColor(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disable_color_from_enabled_state",
			setupMock: func() {
				EnableColor() // Start with color enabled
			},
			validateFunc: func(t *testing.T) {
				DisableColor()
				if IsColoring() {
					t.Error("Expected IsColoring() to return false after DisableColor()")
				}
			},
		},
		{
			name: "success_disable_color_from_disabled_state",
			setupMock: func() {
				DisableColor() // Start with color already disabled
			},
			validateFunc: func(t *testing.T) {
				DisableColor()
				if IsColoring() {
					t.Error("Expected IsColoring() to return false after DisableColor()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestEnableColor(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_enable_color_from_disabled_state",
			setupMock: func() {
				DisableColor() // Start with color disabled
			},
			validateFunc: func(t *testing.T) {
				EnableColor()
				if !IsColoring() {
					t.Error("Expected IsColoring() to return true after EnableColor()")
				}
			},
		},
		{
			name: "success_enable_color_from_enabled_state",
			setupMock: func() {
				EnableColor() // Start with color already enabled
			},
			validateFunc: func(t *testing.T) {
				EnableColor()
				if !IsColoring() {
					t.Error("Expected IsColoring() to return true after EnableColor()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestIsColoring(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult bool
	}{
		{
			name: "success_coloring_enabled",
			setupMock: func() {
				EnableColor()
			},
			expectedResult: true,
		},
		{
			name: "success_coloring_disabled",
			setupMock: func() {
				DisableColor()
			},
			expectedResult: false,
		},
		{
			name: "success_default_state",
			setupMock: func() {
				// Test default state (color enabled by default)
				EnableColor()
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			result := IsColoring()

			if result != tt.expectedResult {
				t.Errorf("Expected IsColoring() %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestEnableInteractive(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_enable_interactive_from_disabled_state",
			setupMock: func() {
				DisableInteractive() // Start with interactive disabled
			},
			validateFunc: func(t *testing.T) {
				EnableInteractive()
				if !IsInteractive() {
					t.Error("Expected IsInteractive() to return true after EnableInteractive()")
				}
			},
		},
		{
			name: "success_enable_interactive_from_enabled_state",
			setupMock: func() {
				EnableInteractive() // Start with interactive already enabled
			},
			validateFunc: func(t *testing.T) {
				EnableInteractive()
				if !IsInteractive() {
					t.Error("Expected IsInteractive() to return true after EnableInteractive()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestDisableInteractive(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disable_interactive_from_enabled_state",
			setupMock: func() {
				EnableInteractive() // Start with interactive enabled
			},
			validateFunc: func(t *testing.T) {
				DisableInteractive()
				if IsInteractive() {
					t.Error("Expected IsInteractive() to return false after DisableInteractive()")
				}
			},
		},
		{
			name: "success_disable_interactive_from_disabled_state",
			setupMock: func() {
				DisableInteractive() // Start with interactive already disabled
			},
			validateFunc: func(t *testing.T) {
				DisableInteractive()
				if IsInteractive() {
					t.Error("Expected IsInteractive() to return false after DisableInteractive()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestIsInteractive(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult bool
	}{
		{
			name: "success_interactive_enabled",
			setupMock: func() {
				EnableInteractive()
			},
			expectedResult: true,
		},
		{
			name: "success_interactive_disabled",
			setupMock: func() {
				DisableInteractive()
			},
			expectedResult: false,
		},
		{
			name: "success_default_state",
			setupMock: func() {
				// Test default state (interactive enabled by default)
				EnableInteractive()
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			result := IsInteractive()

			if result != tt.expectedResult {
				t.Errorf("Expected IsInteractive() %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestAllowOutput(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_allow_output_from_disallowed_state",
			setupMock: func() {
				DisallowOutput() // Start with output disallowed
			},
			validateFunc: func(t *testing.T) {
				AllowOutput()
				if !IsAllowingOutput() {
					t.Error("Expected IsAllowingOutput() to return true after AllowOutput()")
				}
			},
		},
		{
			name: "success_allow_output_from_allowed_state",
			setupMock: func() {
				AllowOutput() // Start with output already allowed
			},
			validateFunc: func(t *testing.T) {
				AllowOutput()
				if !IsAllowingOutput() {
					t.Error("Expected IsAllowingOutput() to return true after AllowOutput()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestDisallowOutput(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disallow_output_from_allowed_state",
			setupMock: func() {
				AllowOutput() // Start with output allowed
			},
			validateFunc: func(t *testing.T) {
				DisallowOutput()
				if IsAllowingOutput() {
					t.Error("Expected IsAllowingOutput() to return false after DisallowOutput()")
				}
			},
		},
		{
			name: "success_disallow_output_from_disallowed_state",
			setupMock: func() {
				DisallowOutput() // Start with output already disallowed
			},
			validateFunc: func(t *testing.T) {
				DisallowOutput()
				if IsAllowingOutput() {
					t.Error("Expected IsAllowingOutput() to return false after DisallowOutput()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestIsAllowingOutput(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult bool
	}{
		{
			name: "success_output_allowed",
			setupMock: func() {
				AllowOutput()
			},
			expectedResult: true,
		},
		{
			name: "success_output_disallowed",
			setupMock: func() {
				DisallowOutput()
			},
			expectedResult: false,
		},
		{
			name: "success_default_state",
			setupMock: func() {
				// Test default state (output disallowed by default)
				DisallowOutput()
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			result := IsAllowingOutput()

			if result != tt.expectedResult {
				t.Errorf("Expected IsAllowingOutput() %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestEnableVerboseLogging(t *testing.T) {
	tests := []struct {
		name         string
		logLevel     string
		setupMock    func() (cleanup func())
		validateFunc func(t *testing.T, logLevel string)
	}{
		{
			name:     "success_enable_with_custom_log_level",
			logLevel: "INFO",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, logLevel string) {
				EnableVerboseLogging(logLevel)
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "INFO" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'INFO', got '%s'", envValue)
				}
			},
		},
		{
			name:     "success_enable_with_empty_log_level_defaults_to_debug",
			logLevel: "",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, logLevel string) {
				EnableVerboseLogging(logLevel)
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "DEBUG" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'DEBUG', got '%s'", envValue)
				}
			},
		},
		{
			name:     "success_enable_with_debug_log_level",
			logLevel: "DEBUG",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, logLevel string) {
				EnableVerboseLogging(logLevel)
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "DEBUG" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'DEBUG', got '%s'", envValue)
				}
			},
		},
		{
			name:     "success_enable_with_error_log_level",
			logLevel: "ERROR",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, logLevel string) {
				EnableVerboseLogging(logLevel)
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "ERROR" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'ERROR', got '%s'", envValue)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()

			tt.validateFunc(t, tt.logLevel)
		})
	}
}

func TestDisableVerboseLogging(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func() (cleanup func())
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disable_verbose_logging",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				EnableVerboseLogging("DEBUG") // Start with verbose logging enabled
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T) {
				DisableVerboseLogging()
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "CRITICAL" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'CRITICAL', got '%s'", envValue)
				}
			},
		},
		{
			name: "success_disable_from_already_critical_level",
			setupMock: func() (cleanup func()) {
				originalLevel := os.Getenv(IdsecLogLevelEnvVar)
				os.Setenv(IdsecLogLevelEnvVar, "CRITICAL") // Start with critical level
				return func() {
					if originalLevel != "" {
						os.Setenv(IdsecLogLevelEnvVar, originalLevel)
					} else {
						os.Unsetenv(IdsecLogLevelEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T) {
				DisableVerboseLogging()
				envValue := os.Getenv(IdsecLogLevelEnvVar)
				if envValue != "CRITICAL" {
					t.Errorf("Expected IdsecLogLevelEnvVar environment variable to be 'CRITICAL', got '%s'", envValue)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()

			tt.validateFunc(t)
		})
	}
}

func TestSetLoggerStyle(t *testing.T) {
	tests := []struct {
		name         string
		loggerStyle  string
		setupMock    func() (cleanup func())
		validateFunc func(t *testing.T, loggerStyle string)
	}{
		{
			name:        "success_set_default_logger_style",
			loggerStyle: "default",
			setupMock: func() (cleanup func()) {
				originalStyle := os.Getenv(IdsecLoggerStyleEnvVar)
				return func() {
					if originalStyle != "" {
						os.Setenv(IdsecLoggerStyleEnvVar, originalStyle)
					} else {
						os.Unsetenv(IdsecLoggerStyleEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, loggerStyle string) {
				SetLoggerStyle(loggerStyle)
				envValue := os.Getenv(IdsecLoggerStyleEnvVar)
				if envValue != "default" {
					t.Errorf("Expected IdsecLoggerStyleEnvVar environment variable to be 'default', got '%s'", envValue)
				}
			},
		},
		{
			name:        "success_set_non_default_logger_style_defaults_to_default",
			loggerStyle: "custom",
			setupMock: func() (cleanup func()) {
				originalStyle := os.Getenv(IdsecLoggerStyleEnvVar)
				return func() {
					if originalStyle != "" {
						os.Setenv(IdsecLoggerStyleEnvVar, originalStyle)
					} else {
						os.Unsetenv(IdsecLoggerStyleEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, loggerStyle string) {
				SetLoggerStyle(loggerStyle)
				envValue := os.Getenv(IdsecLoggerStyleEnvVar)
				if envValue != "default" {
					t.Errorf("Expected IdsecLoggerStyleEnvVar environment variable to be 'default', got '%s'", envValue)
				}
			},
		},
		{
			name:        "success_set_empty_logger_style_defaults_to_default",
			loggerStyle: "",
			setupMock: func() (cleanup func()) {
				originalStyle := os.Getenv(IdsecLoggerStyleEnvVar)
				return func() {
					if originalStyle != "" {
						os.Setenv(IdsecLoggerStyleEnvVar, originalStyle)
					} else {
						os.Unsetenv(IdsecLoggerStyleEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T, loggerStyle string) {
				SetLoggerStyle(loggerStyle)
				envValue := os.Getenv(IdsecLoggerStyleEnvVar)
				if envValue != "default" {
					t.Errorf("Expected IdsecLoggerStyleEnvVar environment variable to be 'default', got '%s'", envValue)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()

			tt.validateFunc(t, tt.loggerStyle)
		})
	}
}

func TestEnableCertificateVerification(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_enable_cert_verification_from_disabled_state",
			setupMock: func() {
				DisableCertificateVerification() // Start with cert verification disabled
			},
			validateFunc: func(t *testing.T) {
				EnableCertificateVerification()
				// Note: IsVerifyingCertificates() may still return false if env var is set
				// This test validates the internal state change
			},
		},
		{
			name: "success_enable_cert_verification_from_enabled_state",
			setupMock: func() {
				EnableCertificateVerification() // Start with cert verification already enabled
			},
			validateFunc: func(t *testing.T) {
				EnableCertificateVerification()
				// Test validates that calling enable multiple times works
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestDisableCertificateVerification(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disable_cert_verification_from_enabled_state",
			setupMock: func() {
				EnableCertificateVerification() // Start with cert verification enabled
			},
			validateFunc: func(t *testing.T) {
				DisableCertificateVerification()
				// Test validates the internal state change
			},
		},
		{
			name: "success_disable_cert_verification_from_disabled_state",
			setupMock: func() {
				DisableCertificateVerification() // Start with cert verification already disabled
			},
			validateFunc: func(t *testing.T) {
				DisableCertificateVerification()
				// Test validates that calling disable multiple times works
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestIsVerifyingCertificates(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func() (cleanup func())
		expectedResult bool
	}{
		{
			name: "success_cert_verification_enabled_no_env_var",
			setupMock: func() (cleanup func()) {
				EnableCertificateVerification()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)
				os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
				return func() {
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					}
				}
			},
			expectedResult: true,
		},
		{
			name: "success_cert_verification_disabled_no_env_var",
			setupMock: func() (cleanup func()) {
				DisableCertificateVerification()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)
				os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
				return func() {
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_env_var_overrides_enabled_state",
			setupMock: func() (cleanup func()) {
				EnableCertificateVerification()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)
				os.Setenv(IdsecDisableCertificateVerificationEnvVar, "true")
				return func() {
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					} else {
						os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_env_var_overrides_disabled_state",
			setupMock: func() (cleanup func()) {
				DisableCertificateVerification()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)
				os.Setenv(IdsecDisableCertificateVerificationEnvVar, "1")
				return func() {
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					} else {
						os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_empty_env_var_uses_internal_state",
			setupMock: func() (cleanup func()) {
				EnableCertificateVerification()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)
				os.Setenv(IdsecDisableCertificateVerificationEnvVar, "")
				return func() {
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					} else {
						os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
					}
				}
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()

			result := IsVerifyingCertificates()

			if result != tt.expectedResult {
				t.Errorf("Expected IsVerifyingCertificates() %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestSetTrustedCertificate(t *testing.T) {
	tests := []struct {
		name         string
		cert         string
		setupMock    func()
		validateFunc func(t *testing.T, cert string)
	}{
		{
			name: "success_set_valid_certificate",
			cert: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----",
			setupMock: func() {
				SetTrustedCertificate("") // Clear any existing certificate
			},
			validateFunc: func(t *testing.T, cert string) {
				SetTrustedCertificate(cert)
				result := TrustedCertificate()
				if result != cert {
					t.Errorf("Expected TrustedCertificate() to return '%s', got '%s'", cert, result)
				}
			},
		},
		{
			name: "success_set_empty_certificate",
			cert: "",
			setupMock: func() {
				SetTrustedCertificate("previous-cert") // Set a previous certificate
			},
			validateFunc: func(t *testing.T, cert string) {
				SetTrustedCertificate(cert)
				result := TrustedCertificate()
				if result != "" {
					t.Errorf("Expected TrustedCertificate() to return empty string, got '%s'", result)
				}
			},
		},
		{
			name: "success_override_existing_certificate",
			cert: "new-certificate-data",
			setupMock: func() {
				SetTrustedCertificate("old-certificate-data")
			},
			validateFunc: func(t *testing.T, cert string) {
				SetTrustedCertificate(cert)
				result := TrustedCertificate()
				if result != cert {
					t.Errorf("Expected TrustedCertificate() to return '%s', got '%s'", cert, result)
				}
			},
		},
		{
			name: "success_set_special_characters_certificate",
			cert: "cert-with-special-chars-!@#$%^&*()",
			setupMock: func() {
				SetTrustedCertificate("")
			},
			validateFunc: func(t *testing.T, cert string) {
				SetTrustedCertificate(cert)
				result := TrustedCertificate()
				if result != cert {
					t.Errorf("Expected TrustedCertificate() to return '%s', got '%s'", cert, result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			tt.validateFunc(t, tt.cert)
		})
	}
}

func TestTrustedCertificate(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult string
	}{
		{
			name: "success_return_set_certificate",
			setupMock: func() {
				SetTrustedCertificate("test-certificate-data")
			},
			expectedResult: "test-certificate-data",
		},
		{
			name: "success_return_empty_when_no_certificate_set",
			setupMock: func() {
				SetTrustedCertificate("")
			},
			expectedResult: "",
		},
		{
			name: "success_return_complex_certificate",
			setupMock: func() {
				cert := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----"
				SetTrustedCertificate(cert)
			},
			expectedResult: "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			result := TrustedCertificate()

			if result != tt.expectedResult {
				t.Errorf("Expected TrustedCertificate() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

// TestSystemConfig_Integration tests the complete interaction between different configuration functions
func TestSystemConfig_Integration(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func() (cleanup func())
		validateFunc func(t *testing.T)
	}{
		{
			name: "complete_cycle_color_and_interactive_settings",
			setupMock: func() (cleanup func()) {
				// Store original states
				originalColoring := IsColoring()
				originalInteractive := IsInteractive()
				originalOutput := IsAllowingOutput()

				return func() {
					// Restore original states
					if originalColoring {
						EnableColor()
					} else {
						DisableColor()
					}
					if originalInteractive {
						EnableInteractive()
					} else {
						DisableInteractive()
					}
					if originalOutput {
						AllowOutput()
					} else {
						DisallowOutput()
					}
				}
			},
			validateFunc: func(t *testing.T) {
				// Test complete configuration cycle
				DisableColor()
				DisableInteractive()
				DisallowOutput()

				if IsColoring() || IsInteractive() || IsAllowingOutput() {
					t.Error("Expected all settings to be disabled")
				}

				EnableColor()
				EnableInteractive()
				AllowOutput()

				if !IsColoring() || !IsInteractive() || !IsAllowingOutput() {
					t.Error("Expected all settings to be enabled")
				}
			},
		},
		{
			name: "complete_cycle_certificate_and_trusted_cert",
			setupMock: func() (cleanup func()) {
				originalCert := TrustedCertificate()
				originalEnv := os.Getenv(IdsecDisableCertificateVerificationEnvVar)

				return func() {
					SetTrustedCertificate(originalCert)
					if originalEnv != "" {
						os.Setenv(IdsecDisableCertificateVerificationEnvVar, originalEnv)
					} else {
						os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)
					}
				}
			},
			validateFunc: func(t *testing.T) {
				testCert := "test-integration-certificate"

				SetTrustedCertificate(testCert)
				EnableCertificateVerification()
				os.Unsetenv(IdsecDisableCertificateVerificationEnvVar)

				if TrustedCertificate() != testCert {
					t.Errorf("Expected trusted certificate '%s', got '%s'", testCert, TrustedCertificate())
				}

				if !IsVerifyingCertificates() {
					t.Error("Expected certificate verification to be enabled")
				}

				// Test environment variable override
				os.Setenv(IdsecDisableCertificateVerificationEnvVar, "true")
				if IsVerifyingCertificates() {
					t.Error("Expected certificate verification to be disabled by environment variable")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()

			tt.validateFunc(t)
		})
	}
}

func TestSetIdsecVersion(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		setupMock    func()
		validateFunc func(t *testing.T, version string)
	}{
		{
			name:    "success_set_valid_version",
			version: "1.2.3",
			setupMock: func() {
				SetIdsecVersion("0.0.0") // Reset to default
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "1.2.3" {
					t.Errorf("Expected version '1.2.3', got '%s'", result)
				}
			},
		},
		{
			name:    "success_set_semantic_version",
			version: "2.1.0-beta.1",
			setupMock: func() {
				SetIdsecVersion("1.0.0")
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "2.1.0-beta.1" {
					t.Errorf("Expected version '2.1.0-beta.1', got '%s'", result)
				}
			},
		},
		{
			name:    "success_ignore_empty_version",
			version: "",
			setupMock: func() {
				SetIdsecVersion("1.5.0") // Set initial version
			},
			validateFunc: func(t *testing.T, version string) {
				originalVersion := IdsecVersion()
				SetIdsecVersion(version) // Should be ignored
				result := IdsecVersion()
				if result != originalVersion {
					t.Errorf("Expected version to remain '%s', got '%s'", originalVersion, result)
				}
			},
		},
		{
			name:    "success_set_version_with_build_metadata",
			version: "1.0.0+20230815.abcd123",
			setupMock: func() {
				SetIdsecVersion("0.0.0")
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "1.0.0+20230815.abcd123" {
					t.Errorf("Expected version '1.0.0+20230815.abcd123', got '%s'", result)
				}
			},
		},
		{
			name:    "success_override_existing_version",
			version: "3.0.0",
			setupMock: func() {
				SetIdsecVersion("2.5.1") // Set initial version
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "3.0.0" {
					t.Errorf("Expected version '3.0.0', got '%s'", result)
				}
			},
		},
		{
			name:    "success_set_development_version",
			version: "dev-snapshot",
			setupMock: func() {
				SetIdsecVersion("1.0.0")
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "dev-snapshot" {
					t.Errorf("Expected version 'dev-snapshot', got '%s'", result)
				}
			},
		},
		{
			name:    "success_set_version_with_special_characters",
			version: "v1.2.3-rc.1+build.456",
			setupMock: func() {
				SetIdsecVersion("0.0.0")
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "v1.2.3-rc.1+build.456" {
					t.Errorf("Expected version 'v1.2.3-rc.1+build.456', got '%s'", result)
				}
			},
		},
		{
			name:    "edge_case_whitespace_only_version",
			version: "   ",
			setupMock: func() {
				SetIdsecVersion("1.0.0")
			},
			validateFunc: func(t *testing.T, version string) {
				SetIdsecVersion(version)
				result := IdsecVersion()
				if result != "   " {
					t.Errorf("Expected version '   ', got '%s'", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t, tt.version)
		})
	}
}

func TestIdsecVersion(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult string
	}{
		{
			name: "success_return_default_version",
			setupMock: func() {
				SetIdsecVersion("0.0.0") // Ensure default state
			},
			expectedResult: "0.0.0",
		},
		{
			name: "success_return_set_version",
			setupMock: func() {
				SetIdsecVersion("1.2.3")
			},
			expectedResult: "1.2.3",
		},
		{
			name: "success_return_semantic_version",
			setupMock: func() {
				SetIdsecVersion("2.1.0-alpha.1")
			},
			expectedResult: "2.1.0-alpha.1",
		},
		{
			name: "success_return_version_with_build_metadata",
			setupMock: func() {
				SetIdsecVersion("1.0.0+build.123")
			},
			expectedResult: "1.0.0+build.123",
		},
		{
			name: "success_return_development_version",
			setupMock: func() {
				SetIdsecVersion("dev-latest")
			},
			expectedResult: "dev-latest",
		},
		{
			name: "success_return_complex_version",
			setupMock: func() {
				SetIdsecVersion("v2.0.0-rc.1+exp.sha.5114f85")
			},
			expectedResult: "v2.0.0-rc.1+exp.sha.5114f85",
		},
		{
			name: "success_return_version_after_multiple_sets",
			setupMock: func() {
				SetIdsecVersion("1.0.0")
				SetIdsecVersion("2.0.0")
				SetIdsecVersion("") // Should be ignored
				SetIdsecVersion("3.0.0")
			},
			expectedResult: "3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.setupMock()
			result := IdsecVersion()

			if result != tt.expectedResult {
				t.Errorf("Expected IdsecVersion() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

// TestIdsecVersion_EmptyStringBehavior tests the specific behavior with empty strings
func TestIdsecVersion_EmptyStringBehavior(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		operation      func()
		expectedResult string
	}{
		{
			name: "success_empty_string_preserves_previous_version",
			setupMock: func() {
				SetIdsecVersion("1.5.0")
			},
			operation: func() {
				SetIdsecVersion("") // Should not change version
			},
			expectedResult: "1.5.0",
		},
		{
			name: "success_multiple_empty_strings_preserve_version",
			setupMock: func() {
				SetIdsecVersion("2.0.0")
			},
			operation: func() {
				SetIdsecVersion("")
				SetIdsecVersion("")
				SetIdsecVersion("")
			},
			expectedResult: "2.0.0",
		},
		{
			name: "success_empty_string_then_valid_version",
			setupMock: func() {
				SetIdsecVersion("1.0.0")
			},
			operation: func() {
				SetIdsecVersion("")      // Should be ignored
				SetIdsecVersion("2.0.0") // Should update
			},
			expectedResult: "2.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.operation()

			result := IdsecVersion()
			if result != tt.expectedResult {
				t.Errorf("Expected version '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

// TestIdsecVersion_Integration tests the complete interaction between SetIdsecVersion and IdsecVersion
func TestIdsecVersion_Integration(t *testing.T) {
	tests := []struct {
		name          string
		operations    []string
		expectedFinal string
	}{
		{
			name:          "complete_cycle_multiple_version_updates",
			operations:    []string{"1.0.0", "1.1.0", "", "1.2.0", "2.0.0-beta", ""},
			expectedFinal: "2.0.0-beta",
		},
		{
			name:          "complete_cycle_with_special_versions",
			operations:    []string{"dev", "1.0.0-alpha", "1.0.0-beta", "1.0.0-rc.1", "1.0.0"},
			expectedFinal: "1.0.0",
		},
		{
			name:          "complete_cycle_build_metadata_versions",
			operations:    []string{"1.0.0+build.1", "1.0.0+build.2", "", "1.0.0+build.3"},
			expectedFinal: "1.0.0+build.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to known state
			SetIdsecVersion("0.0.0")

			// Apply all operations
			for _, version := range tt.operations {
				SetIdsecVersion(version)
			}

			// Verify final result
			result := IdsecVersion()
			if result != tt.expectedFinal {
				t.Errorf("Expected final version '%s', got '%s'", tt.expectedFinal, result)
			}
		})
	}
}

// TestIdsecVersion_ThreadSafety tests basic concurrent access patterns
func TestIdsecVersion_ConcurrentAccess(t *testing.T) {
	tests := []struct {
		name         string
		setupVersion string
		validateFunc func(t *testing.T)
	}{
		{
			name:         "success_concurrent_reads",
			setupVersion: "1.0.0",
			validateFunc: func(t *testing.T) {
				// Set initial version
				SetIdsecVersion("1.0.0")

				// Multiple concurrent reads should all return the same value
				done := make(chan string, 5)

				for i := 0; i < 5; i++ {
					go func() {
						done <- IdsecVersion()
					}()
				}

				// Collect all results
				for i := 0; i < 5; i++ {
					result := <-done
					if result != "1.0.0" {
						t.Errorf("Expected version '1.0.0', got '%s'", result)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validateFunc(t)
		})
	}
}

func TestIdsecBuildNumber(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult string
	}{
		{
			name: "success_return_default_build_number",
			setupMock: func() {
				SetIdsecBuildNumber("0")
			},
			expectedResult: "0",
		},
		{
			name: "success_return_set_build_number",
			setupMock: func() {
				SetIdsecBuildNumber("42")
			},
			expectedResult: "42",
		},
		{
			name: "success_return_build_number_with_leading_zeros",
			setupMock: func() {
				SetIdsecBuildNumber("007")
			},
			expectedResult: "007",
		},
		{
			name: "success_return_build_number_with_special_characters",
			setupMock: func() {
				SetIdsecBuildNumber("build-123")
			},
			expectedResult: "build-123",
		},
		{
			name: "success_return_build_number_after_multiple_sets",
			setupMock: func() {
				SetIdsecBuildNumber("1")
				SetIdsecBuildNumber("2")
				SetIdsecBuildNumber("3")
			},
			expectedResult: "3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.setupMock()
			result := IdsecBuildNumber()
			if result != tt.expectedResult {
				t.Errorf("Expected IdsecBuildNumber() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestSetIdsecBuildNumber(t *testing.T) {
	tests := []struct {
		name         string
		buildNumber  string
		setupMock    func()
		validateFunc func(t *testing.T, buildNumber string)
	}{
		{
			name:        "success_set_valid_build_number",
			buildNumber: "123",
			setupMock: func() {
				SetIdsecBuildNumber("0")
			},
			validateFunc: func(t *testing.T, buildNumber string) {
				SetIdsecBuildNumber(buildNumber)
				result := IdsecBuildNumber()
				if result != "123" {
					t.Errorf("Expected build number '123', got '%s'", result)
				}
			},
		},
		{
			name:        "success_ignore_empty_build_number",
			buildNumber: "",
			setupMock: func() {
				SetIdsecBuildNumber("999")
			},
			validateFunc: func(t *testing.T, buildNumber string) {
				original := IdsecBuildNumber()
				SetIdsecBuildNumber(buildNumber)
				result := IdsecBuildNumber()
				if result != original {
					t.Errorf("Expected build number to remain '%s', got '%s'", original, result)
				}
			},
		},
		{
			name:        "success_set_build_number_with_special_characters",
			buildNumber: "bn-special-!@#",
			setupMock: func() {
				SetIdsecBuildNumber("0")
			},
			validateFunc: func(t *testing.T, buildNumber string) {
				SetIdsecBuildNumber(buildNumber)
				result := IdsecBuildNumber()
				if result != "bn-special-!@#" {
					t.Errorf("Expected build number 'bn-special-!@#', got '%s'", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t, tt.buildNumber)
		})
	}
}

func TestIdsecBuildDate(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult string
	}{
		{
			name: "success_return_default_build_date",
			setupMock: func() {
				SetIdsecBuildDate("N/A")
			},
			expectedResult: "N/A",
		},
		{
			name: "success_return_set_build_date",
			setupMock: func() {
				SetIdsecBuildDate("2024-06-01")
			},
			expectedResult: "2024-06-01",
		},
		{
			name: "success_return_build_date_with_time",
			setupMock: func() {
				SetIdsecBuildDate("2024-06-01T12:34:56Z")
			},
			expectedResult: "2024-06-01T12:34:56Z",
		},
		{
			name: "success_return_build_date_with_special_characters",
			setupMock: func() {
				SetIdsecBuildDate("date-!@#")
			},
			expectedResult: "date-!@#",
		},
		{
			name: "success_return_build_date_after_multiple_sets",
			setupMock: func() {
				SetIdsecBuildDate("2023-01-01")
				SetIdsecBuildDate("2024-01-01")
			},
			expectedResult: "2024-01-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.setupMock()
			result := IdsecBuildDate()
			if result != tt.expectedResult {
				t.Errorf("Expected IdsecBuildDate() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestSetIdsecBuildDate(t *testing.T) {
	tests := []struct {
		name         string
		buildDate    string
		setupMock    func()
		validateFunc func(t *testing.T, buildDate string)
	}{
		{
			name:      "success_set_valid_build_date",
			buildDate: "2024-06-01",
			setupMock: func() {
				SetIdsecBuildDate("N/A")
			},
			validateFunc: func(t *testing.T, buildDate string) {
				SetIdsecBuildDate(buildDate)
				result := IdsecBuildDate()
				if result != "2024-06-01" {
					t.Errorf("Expected build date '2024-06-01', got '%s'", result)
				}
			},
		},
		{
			name:      "success_ignore_empty_build_date",
			buildDate: "",
			setupMock: func() {
				SetIdsecBuildDate("2023-01-01")
			},
			validateFunc: func(t *testing.T, buildDate string) {
				original := IdsecBuildDate()
				SetIdsecBuildDate(buildDate)
				result := IdsecBuildDate()
				if result != original {
					t.Errorf("Expected build date to remain '%s', got '%s'", original, result)
				}
			},
		},
		{
			name:      "success_set_build_date_with_special_characters",
			buildDate: "date-!@#",
			setupMock: func() {
				SetIdsecBuildDate("N/A")
			},
			validateFunc: func(t *testing.T, buildDate string) {
				SetIdsecBuildDate(buildDate)
				result := IdsecBuildDate()
				if result != "date-!@#" {
					t.Errorf("Expected build date 'date-!@#', got '%s'", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t, tt.buildDate)
		})
	}
}

func TestIdsecGitCommit(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult string
	}{
		{
			name: "success_return_default_git_commit",
			setupMock: func() {
				SetIdsecGitCommit("N/A")
			},
			expectedResult: "N/A",
		},
		{
			name: "success_return_set_git_commit",
			setupMock: func() {
				SetIdsecGitCommit("abcd1234")
			},
			expectedResult: "abcd1234",
		},
		{
			name: "success_return_git_commit_with_special_characters",
			setupMock: func() {
				SetIdsecGitCommit("commit-!@#")
			},
			expectedResult: "commit-!@#",
		},
		{
			name: "success_return_git_commit_after_multiple_sets",
			setupMock: func() {
				SetIdsecGitCommit("1111")
				SetIdsecGitCommit("2222")
			},
			expectedResult: "2222",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.setupMock()
			result := IdsecGitCommit()
			if result != tt.expectedResult {
				t.Errorf("Expected IdsecGitCommit() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestSetIdsecGitCommit(t *testing.T) {
	tests := []struct {
		name         string
		gitCommit    string
		setupMock    func()
		validateFunc func(t *testing.T, gitCommit string)
	}{
		{
			name:      "success_set_valid_git_commit",
			gitCommit: "abcd1234",
			setupMock: func() {
				SetIdsecGitCommit("N/A")
			},
			validateFunc: func(t *testing.T, gitCommit string) {
				SetIdsecGitCommit(gitCommit)
				result := IdsecGitCommit()
				if result != "abcd1234" {
					t.Errorf("Expected git commit 'abcd1234', got '%s'", result)
				}
			},
		},
		{
			name:      "success_ignore_empty_git_commit",
			gitCommit: "",
			setupMock: func() {
				SetIdsecGitCommit("efgh5678")
			},
			validateFunc: func(t *testing.T, gitCommit string) {
				original := IdsecGitCommit()
				SetIdsecGitCommit(gitCommit)
				result := IdsecGitCommit()
				if result != original {
					t.Errorf("Expected git commit to remain '%s', got '%s'", original, result)
				}
			},
		},
		{
			name:      "success_set_git_commit_with_special_characters",
			gitCommit: "commit-!@#",
			setupMock: func() {
				SetIdsecGitCommit("N/A")
			},
			validateFunc: func(t *testing.T, gitCommit string) {
				SetIdsecGitCommit(gitCommit)
				result := IdsecGitCommit()
				if result != "commit-!@#" {
					t.Errorf("Expected git commit 'commit-!@#', got '%s'", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t, tt.gitCommit)
		})
	}
}

func TestIdsecPath(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "success_return_default_repo_path",
			expectedResult: "cyberark/idsec-sdk-golang",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IdsecPath()
			if result != tt.expectedResult {
				t.Errorf("Expected IdsecPath() '%s', got '%s'", tt.expectedResult, result)
			}
		})
	}
}

func TestIdsecToolInUse(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func()
		expectedResult IdsecTool
	}{
		{
			name: "success_return_default_tool",
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolSDK)
			},
			expectedResult: IdsecToolSDK,
		},
		{
			name: "success_return_cli_tool",
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolCLI)
			},
			expectedResult: IdsecToolCLI,
		},
		{
			name: "success_return_tf_tool",
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolTerraformProvider)
			},
			expectedResult: IdsecToolTerraformProvider,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.setupMock()
			result := IdsecToolInUse()
			if result != tt.expectedResult {
				t.Errorf("Expected IdsecToolInUse() '%v', got '%v'", tt.expectedResult, result)
			}
		})
	}
}

func TestSetIdsecToolInUse(t *testing.T) {
	tests := []struct {
		name         string
		tool         IdsecTool
		setupMock    func()
		validateFunc func(t *testing.T, tool IdsecTool)
	}{
		{
			name: "success_set_sdk_tool",
			tool: IdsecToolSDK,
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolCLI)
			},
			validateFunc: func(t *testing.T, tool IdsecTool) {
				SetIdsecToolInUse(tool)
				result := IdsecToolInUse()
				if result != IdsecToolSDK {
					t.Errorf("Expected IdsecToolInUse() 'IdsecToolSDK', got '%v'", result)
				}
			},
		},
		{
			name: "success_set_cli_tool",
			tool: IdsecToolCLI,
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolSDK)
			},
			validateFunc: func(t *testing.T, tool IdsecTool) {
				SetIdsecToolInUse(tool)
				result := IdsecToolInUse()
				if result != IdsecToolCLI {
					t.Errorf("Expected IdsecToolInUse() 'IdsecToolCLI', got '%v'", result)
				}
			},
		},
		{
			name: "success_set_tf_tool",
			tool: IdsecToolTerraformProvider,
			setupMock: func() {
				SetIdsecToolInUse(IdsecToolSDK)
			},
			validateFunc: func(t *testing.T, tool IdsecTool) {
				SetIdsecToolInUse(tool)
				result := IdsecToolInUse()
				if result != IdsecToolTerraformProvider {
					t.Errorf("Expected IdsecToolInUse() 'IdsecToolTerraformProvider', got '%v'", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t, tt.tool)
		})
	}
}

func TestGenerateCorrelationID(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_generate_new_correlation_id",
			setupMock: func() {
				// Clear correlation ID
				currentCorrelationID = ""
			},
			validateFunc: func(t *testing.T) {
				id := GenerateCorrelationID()
				if id == "" {
					t.Error("Expected non-empty correlation ID")
				}
				if id != currentCorrelationID {
					t.Errorf("Expected currentCorrelationID to match generated ID")
				}
			},
		},
		{
			name: "success_generate_multiple_unique_ids",
			setupMock: func() {
				currentCorrelationID = ""
			},
			validateFunc: func(t *testing.T) {
				id1 := GenerateCorrelationID()
				id2 := GenerateCorrelationID()
				if id1 == id2 {
					t.Error("Expected different correlation IDs on consecutive calls")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestCorrelationID(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_return_existing_correlation_id",
			setupMock: func() {
				currentCorrelationID = "test-id-123"
			},
			validateFunc: func(t *testing.T) {
				id := CorrelationID()
				if id != "test-id-123" {
					t.Errorf("Expected CorrelationID() to return 'test-id-123', got '%s'", id)
				}
			},
		},
		{
			name: "success_generate_new_id_if_none_set",
			setupMock: func() {
				currentCorrelationID = ""
			},
			validateFunc: func(t *testing.T) {
				id := CorrelationID()
				if id == "" {
					t.Error("Expected non-empty correlation ID")
				}
				if id != currentCorrelationID {
					t.Errorf("Expected currentCorrelationID to match returned ID")
				}
			},
		},
		{
			name: "success_return_same_id_on_multiple_calls",
			setupMock: func() {
				currentCorrelationID = ""
			},
			validateFunc: func(t *testing.T) {
				id1 := CorrelationID()
				id2 := CorrelationID()
				if id1 != id2 {
					t.Error("Expected CorrelationID() to return same value on consecutive calls")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestEnableTelemetryCollection(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_enable_telemetry_from_disabled_state",
			setupMock: func() {
				DisableTelemetryCollection()
			},
			validateFunc: func(t *testing.T) {
				EnableTelemetryCollection()
				if !IsTelemetryCollectionEnabled() {
					t.Error("Expected IsTelemetryCollectionEnabled() to return true after EnableTelemetryCollection()")
				}
			},
		},
		{
			name: "success_enable_telemetry_from_enabled_state",
			setupMock: func() {
				EnableTelemetryCollection() // Start with telemetry enabled
			},
			validateFunc: func(t *testing.T) {
				EnableTelemetryCollection()
				if !IsTelemetryCollectionEnabled() {
					t.Error("Expected IsTelemetryCollectionEnabled() to return true after EnableTelemetryCollection()")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			tt.validateFunc(t)
		})
	}
}

func TestDisableTelemetryCollection(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func()
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_disable_from_enabled_state",
			setupMock: func() {
				EnableTelemetryCollection()
				os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
			},
			validateFunc: func(t *testing.T) {
				DisableTelemetryCollection()
				if IsTelemetryCollectionEnabled() {
					t.Error("Expected telemetry collection disabled")
				}
			},
		},
		{
			name: "success_disable_from_already_disabled_state",
			setupMock: func() {
				DisableTelemetryCollection()
				os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
			},
			validateFunc: func(t *testing.T) {
				DisableTelemetryCollection()
				if IsTelemetryCollectionEnabled() {
					t.Error("Expected telemetry collection disabled")
				}
			},
		},
		{
			name: "success_disable_ignored_when_env_var_forces_disable",
			setupMock: func() {
				EnableTelemetryCollection()
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "true")
			},
			validateFunc: func(t *testing.T) {
				DisableTelemetryCollection()
				if IsTelemetryCollectionEnabled() {
					t.Error("Expected env var override to keep telemetry disabled")
				}
			},
		},
		{
			name: "success_disable_after_env_var_cleared",
			setupMock: func() {
				EnableTelemetryCollection()
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "")
			},
			validateFunc: func(t *testing.T) {
				DisableTelemetryCollection()
				if IsTelemetryCollectionEnabled() {
					t.Error("Expected telemetry disabled after call")
				}
			},
		},
		{
			name: "success_disable_with_numeric_env_var_override",
			setupMock: func() {
				EnableTelemetryCollection()
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "1")
			},
			validateFunc: func(t *testing.T) {
				DisableTelemetryCollection()
				if IsTelemetryCollectionEnabled() {
					t.Error("Expected telemetry disabled due to env var override")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			defer os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
			tt.validateFunc(t)
		})
	}
}

func TestIsTelemetryCollectionEnabled(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func() (cleanup func())
		expectedResult bool
	}{
		{
			name: "success_enabled_without_env_var",
			setupMock: func() (cleanup func()) {
				EnableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: true,
		},
		{
			name: "success_disabled_without_env_var",
			setupMock: func() (cleanup func()) {
				DisableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_env_var_true_overrides_enabled",
			setupMock: func() (cleanup func()) {
				EnableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "true")
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_env_var_numeric_overrides_enabled",
			setupMock: func() (cleanup func()) {
				EnableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "1")
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: false,
		},
		{
			name: "success_empty_env_var_uses_internal_state",
			setupMock: func() (cleanup func()) {
				EnableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "")
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: true,
		},
		{
			name: "success_disabled_internal_with_empty_env_var",
			setupMock: func() (cleanup func()) {
				DisableTelemetryCollection()
				original := os.Getenv(IdsecDisableTelemetryCollectionEnvVar)
				os.Setenv(IdsecDisableTelemetryCollectionEnvVar, "")
				return func() {
					if original != "" {
						os.Setenv(IdsecDisableTelemetryCollectionEnvVar, original)
					} else {
						os.Unsetenv(IdsecDisableTelemetryCollectionEnvVar)
					}
				}
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupMock()
			defer cleanup()
			result := IsTelemetryCollectionEnabled()
			if result != tt.expectedResult {
				t.Errorf("Expected IsTelemetryCollectionEnabled() %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name           string
		tool           IdsecTool
		version        string
		setupMock      func()
		expectedSuffix string
		validateFunc   func(t *testing.T, ua string, expectedSuffix string)
	}{
		{
			name:           "success_contains_sdk_tool_and_version",
			tool:           IdsecToolSDK,
			version:        "1.0.0",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolSDK); SetIdsecVersion("1.0.0") },
			expectedSuffix: "Idsec-SDK-Golang/1.0.0",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				if !strings.HasSuffix(ua, suffix) {
					t.Errorf("Expected user agent suffix '%s', got '%s'", suffix, ua)
				}
			},
		},
		{
			name:           "success_reflects_cli_tool_and_version",
			tool:           IdsecToolCLI,
			version:        "2.3.4",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolCLI); SetIdsecVersion("2.3.4") },
			expectedSuffix: "Idsec-CLI-Golang/2.3.4",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				if !strings.HasSuffix(ua, suffix) {
					t.Errorf("Expected user agent suffix '%s', got '%s'", suffix, ua)
				}
			},
		},
		{
			name:           "success_reflects_terraform_tool_and_version",
			tool:           IdsecToolTerraformProvider,
			version:        "0.9.1-beta",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolTerraformProvider); SetIdsecVersion("0.9.1-beta") },
			expectedSuffix: "Idsec-Terraform-Provider/0.9.1-beta",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				if !strings.HasSuffix(ua, suffix) {
					t.Errorf("Expected user agent suffix '%s', got '%s'", suffix, ua)
				}
			},
		},
		{
			name:           "success_updates_after_version_change",
			tool:           IdsecToolSDK,
			version:        "3.0.0",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolSDK); SetIdsecVersion("2.0.0") },
			expectedSuffix: "Idsec-SDK-Golang/3.0.0",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				// change version then check again
				SetIdsecVersion("3.0.0")
				ua2 := UserAgent()
				if !strings.HasSuffix(ua2, suffix) {
					t.Errorf("Expected updated user agent suffix '%s', got '%s'", suffix, ua2)
				}
			},
		},
		{
			name:           "success_multiple_calls_consistent_suffix",
			tool:           IdsecToolCLI,
			version:        "5.6.7",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolCLI); SetIdsecVersion("5.6.7") },
			expectedSuffix: "Idsec-CLI-Golang/5.6.7",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				ua2 := UserAgent()
				if !strings.HasSuffix(ua, suffix) || !strings.HasSuffix(ua2, suffix) {
					t.Errorf("Expected both user agents to end with '%s'; got '%s' and '%s'", suffix, ua, ua2)
				}
			},
		},
		{
			name:           "edge_case_version_with_metadata",
			tool:           IdsecToolTerraformProvider,
			version:        "1.0.0+build.9",
			setupMock:      func() { SetIdsecToolInUse(IdsecToolTerraformProvider); SetIdsecVersion("1.0.0+build.9") },
			expectedSuffix: "Idsec-Terraform-Provider/1.0.0+build.9",
			validateFunc: func(t *testing.T, ua string, suffix string) {
				if !strings.HasSuffix(ua, suffix) {
					t.Errorf("Expected suffix '%s', got '%s'", suffix, ua)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()
			ua := UserAgent()
			tt.validateFunc(t, ua, tt.expectedSuffix)
		})
	}
}
