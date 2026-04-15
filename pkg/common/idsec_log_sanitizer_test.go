package common

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestSanitizeMessage_JSONKeyValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_password_json",
			input:    `{"password":"s3cret","user":"admin"}`,
			expected: `{"password":"[REDACTED]","user":"admin"}`,
		},
		{
			name:     "success_token_json",
			input:    `{"token":"eyJhbGciOiJIUzI1NiJ9.abc","name":"test"}`,
			expected: `{"token":"[REDACTED]","name":"test"}`,
		},
		{
			name:     "success_refresh_token_json",
			input:    `{"refresh_token":"rt-abc-123","scope":"read"}`,
			expected: `{"refresh_token":"[REDACTED]","scope":"read"}`,
		},
		{
			name:     "success_authorization_json",
			input:    `{"authorization":"Bearer eyJ...","host":"example.com"}`,
			expected: `{"authorization":"[REDACTED]","host":"example.com"}`,
		},
		{
			name:     "success_aws_keys_json",
			input:    `{"aws_secret_access_key":"wJalrXUtnFEMI","aws_session_token":"FwoGZX"}`,
			expected: `{"aws_secret_access_key":"[REDACTED]","aws_session_token":"[REDACTED]"}`,
		},
		{
			name:     "success_private_key_json",
			input:    `{"private_key":"-----BEGIN RSA PRIVATE KEY-----"}`,
			expected: `{"private_key":"[REDACTED]"}`,
		},
		{
			name:     "success_json_with_spaces",
			input:    `{"password" : "s3cret"}`,
			expected: `{"password":"[REDACTED]"}`,
		},
		{
			name:     "success_multiple_sensitive_fields",
			input:    `{"password":"pass1","secret":"s3c","token":"tok1"}`,
			expected: `{"password":"[REDACTED]","secret":"[REDACTED]","token":"[REDACTED]"}`,
		},
		{
			name:     "success_no_sensitive_fields",
			input:    `{"username":"admin","host":"localhost"}`,
			expected: `{"username":"admin","host":"localhost"}`,
		},
		{
			name:     "success_client_secret_json",
			input:    `{"client_secret":"abc123xyz"}`,
			expected: `{"client_secret":"[REDACTED]"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sanitizeMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMessage(%q)\n  got:  %q\n  want: %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeMessage_StructDump(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_password_struct",
			input:    `{Password:s3cret Name:admin}`,
			expected: `{Password:[REDACTED] Name:admin}`,
		},
		{
			name:     "success_token_struct",
			input:    `{Token:eyJhbGciOiJ9 ID:42}`,
			expected: `{Token:[REDACTED] ID:42}`,
		},
		{
			name:     "success_private_key_contents_struct",
			input:    `{PrivateKeyContents:MIIB...== Host:example.com}`,
			expected: `{PrivateKeyContents:[REDACTED] Host:example.com}`,
		},
		{
			name:     "success_credentials_struct",
			input:    `{Credentials:0xc000123abc}`,
			expected: `{Credentials:[REDACTED]}`,
		},
		{
			name:     "success_no_sensitive_struct_fields",
			input:    `{Username:admin Host:localhost}`,
			expected: `{Username:admin Host:localhost}`,
		},
		{
			name:     "success_aws_secret_access_key_struct",
			input:    `{AWSSecretAccessKey:wJalrXUtnFEMI Region:us-east-1}`,
			expected: `{AWSSecretAccessKey:[REDACTED] Region:us-east-1}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sanitizeMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMessage(%q)\n  got:  %q\n  want: %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeMessage_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_uppercase_json",
			input:    `{"PASSWORD":"s3cret"}`,
			expected: `{"PASSWORD":"[REDACTED]"}`,
		},
		{
			name:     "success_mixed_case_json",
			input:    `{"Password":"s3cret"}`,
			expected: `{"Password":"[REDACTED]"}`,
		},
		{
			name:     "success_lowercase_struct",
			input:    `{password:s3cret}`,
			expected: `{password:[REDACTED]}`,
		},
		{
			name:     "success_uppercase_struct",
			input:    `{PASSWORD:s3cret}`,
			expected: `{PASSWORD:[REDACTED]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sanitizeMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMessage(%q)\n  got:  %q\n  want: %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeMessage_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_empty_string",
			input:    "",
			expected: "",
		},
		{
			name:     "success_no_matches",
			input:    "plain log message with no sensitive data",
			expected: "plain log message with no sensitive data",
		},
		{
			name:     "success_mixed_json_and_struct",
			input:    `Error: {"password":"abc"} with context {Token:xyz123 Status:200}`,
			expected: `Error: {"password":"[REDACTED]"} with context {Token:[REDACTED] Status:200}`,
		},
		{
			name:     "success_json_empty_value",
			input:    `{"password":"","name":"test"}`,
			expected: `{"password":"[REDACTED]","name":"test"}`,
		},
		{
			name:     "success_serialized_response_body",
			input:    `failed to authenticate - [401] - [{"token":"eyJ...","error":"invalid_grant","password":"hunter2"}]`,
			expected: `failed to authenticate - [401] - [{"token":"[REDACTED]","error":"invalid_grant","password":"[REDACTED]"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sanitizeMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMessage(%q)\n  got:  %q\n  want: %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeMessage_FileLogIntegration(t *testing.T) {
	originalFilePath := os.Getenv(config.IdsecFileLogPathEnvVar)
	originalFileLevel := os.Getenv(config.IdsecFileLogLevelEnvVar)
	originalTool := config.IdsecToolInUse()
	defer func() {
		if originalFilePath != "" {
			_ = os.Setenv(config.IdsecFileLogPathEnvVar, originalFilePath)
		} else {
			_ = os.Unsetenv(config.IdsecFileLogPathEnvVar)
		}
		if originalFileLevel != "" {
			_ = os.Setenv(config.IdsecFileLogLevelEnvVar, originalFileLevel)
		} else {
			_ = os.Unsetenv(config.IdsecFileLogLevelEnvVar)
		}
		config.SetIdsecToolInUse(originalTool)
	}()
	config.SetIdsecToolInUse(config.IdsecToolCLI)

	filePath := filepath.Join(t.TempDir(), "sanitized.log")
	_ = os.Setenv(config.IdsecFileLogPathEnvVar, filePath)
	_ = os.Setenv(config.IdsecFileLogLevelEnvVar, "DEBUG")

	logger := NewIdsecLogger("test-app", Debug, true, false)
	// Suppress stdout for this test
	logger.Logger = log.New(&bytes.Buffer{}, "test-app", log.LstdFlags)

	logger.Error(`Auth failed: {"password":"hunter2","token":"eyJhbGciOiJ9"}`)

	fileContent, err := os.ReadFile(filePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Failed to read log file: %v", err)
	}
	content := string(fileContent)

	if strings.Contains(content, "hunter2") {
		t.Fatalf("Expected password to be redacted in file log, got: %s", content)
	}
	if strings.Contains(content, "eyJhbGciOiJ9") {
		t.Fatalf("Expected token to be redacted in file log, got: %s", content)
	}
	if !strings.Contains(content, `"password":"[REDACTED]"`) {
		t.Fatalf("Expected redacted password placeholder in file log, got: %s", content)
	}
	if !strings.Contains(content, `"token":"[REDACTED]"`) {
		t.Fatalf("Expected redacted token placeholder in file log, got: %s", content)
	}
	if !strings.Contains(content, "Auth failed") {
		t.Fatalf("Expected non-sensitive parts of the message to be preserved, got: %s", content)
	}
}

func TestSanitizeMessage_ValuePatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_jwt_standalone",
			input:    `auth header: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZXZhbHVl`,
			expected: `auth header: [REDACTED]`,
		},
		{
			name:     "success_aws_access_key_id",
			input:    `using key AKIAIOSFODNN7EXAMPLE for access`,
			expected: `using key [REDACTED] for access`,
		},
		{
			name:     "success_pem_private_key_block",
			input:    `cert: -----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ\n-----END RSA PRIVATE KEY-----`,
			expected: `cert: [REDACTED]`,
		},
		{
			name:     "success_bearer_token",
			input:    `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`,
			expected: `Authorization: [REDACTED]`,
		},
		{
			name:     "success_basic_auth",
			input:    `header: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY=`,
			expected: `header: [REDACTED]`,
		},
		{
			name:     "success_generic_hex_secret",
			input:    `using secret=0123456789abcdef0123456789abcdef01 for auth`,
			expected: `using [REDACTED] for auth`,
		},
		{
			name:     "success_no_false_positive_short_string",
			input:    `id: abc123 status: ok`,
			expected: `id: abc123 status: ok`,
		},
		{
			name:     "success_mixed_field_and_value",
			input:    `{"password":"hunter2"} and standalone AKIAIOSFODNN7EXAMPLE`,
			expected: `{"password":"[REDACTED]"} and standalone [REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := sanitizeMessage(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMessage(%q)\n  got:  %q\n  want: %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildFieldSanitizers(t *testing.T) {
	fields := []string{"password", "token"}
	sanitizers := buildFieldSanitizers(fields)

	if len(sanitizers) != len(fields) {
		t.Fatalf("Expected %d sanitizers, got %d", len(fields), len(sanitizers))
	}
	for i, s := range sanitizers {
		if s.fieldName != fields[i] {
			t.Errorf("Expected field name %q, got %q", fields[i], s.fieldName)
		}
		if s.jsonPattern == nil {
			t.Errorf("Expected JSON pattern for field %q to be compiled", s.fieldName)
		}
		if s.structPattern == nil {
			t.Errorf("Expected struct pattern for field %q to be compiled", s.fieldName)
		}
	}
}
