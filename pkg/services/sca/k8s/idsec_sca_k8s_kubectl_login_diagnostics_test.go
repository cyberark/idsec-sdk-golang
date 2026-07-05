package k8s

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

func TestKubectlLoginLogLevelFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  KubectlLoginLogLevel
	}{
		{"debug_lower", "debug", KubectlLoginLogLevelDebug},
		{"info_mixed_case", "Info", KubectlLoginLogLevelInfo},
		{"warning_full", "WARNING", KubectlLoginLogLevelWarning},
		{"warn_alias", "warn", KubectlLoginLogLevelWarning},
		{"error_word", "ERROR", KubectlLoginLogLevelError},
		{"critical_collapses_to_error", "CRITICAL", KubectlLoginLogLevelError},
		{"fatal_collapses_to_error", "fatal", KubectlLoginLogLevelError},
		{"whitespace_trimmed", "  debug  ", KubectlLoginLogLevelDebug},
		{"empty_defaults_to_debug", "", KubectlLoginLogLevelDebug},
		{"unknown_defaults_to_debug", "verbose", KubectlLoginLogLevelDebug},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KubectlLoginLogLevelFromString(tt.input); got != tt.want {
				t.Fatalf("KubectlLoginLogLevelFromString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestKubectlLoginLogLevelName(t *testing.T) {
	tests := []struct {
		name  string
		level KubectlLoginLogLevel
		want  string
	}{
		{"debug", KubectlLoginLogLevelDebug, "DEBUG"},
		{"info", KubectlLoginLogLevelInfo, "INFO"},
		{"warning", KubectlLoginLogLevelWarning, "WARNING"},
		{"error", KubectlLoginLogLevelError, "ERROR"},
		{"zero_value_defaults_to_debug", KubectlLoginLogLevel(0), "DEBUG"},
		{"out_of_range_defaults_to_debug", KubectlLoginLogLevel(99), "DEBUG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KubectlLoginLogLevelName(tt.level); got != tt.want {
				t.Fatalf("KubectlLoginLogLevelName(%d) = %q, want %q", tt.level, got, tt.want)
			}
		})
	}
}

func TestKubectlLoginLogLine(t *testing.T) {
	t.Run("nil_writer_is_noop", func(t *testing.T) {
		KubectlLoginLogLine(nil, KubectlLoginLogLevelInfo, "should not panic")
	})

	t.Run("formats_prefix_level_and_message", func(t *testing.T) {
		var buf bytes.Buffer
		KubectlLoginLogLine(&buf, KubectlLoginLogLevelWarning, "attempt %d failed", 3)
		out := buf.String()
		if !strings.HasPrefix(out, "kubectl-login | ") {
			t.Fatalf("missing prefix, got: %q", out)
		}
		if !strings.Contains(out, " | WARNING | attempt 3 failed") {
			t.Fatalf("missing level/message, got: %q", out)
		}
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("expected trailing newline, got: %q", out)
		}
	})

	t.Run("strips_embedded_newlines_to_prevent_log_forging", func(t *testing.T) {
		var buf bytes.Buffer
		KubectlLoginLogLine(&buf, KubectlLoginLogLevelInfo, "line1\nINJECTED | line2\rmore")
		out := buf.String()
		if strings.Count(out, "\n") != 1 {
			t.Fatalf("expected exactly one trailing newline, got: %q", out)
		}
		if strings.Contains(out, "\r") {
			t.Fatalf("expected carriage returns stripped, got: %q", out)
		}
	})
}

func TestKubectlLoginLogLevelEnabled(t *testing.T) {
	t.Setenv(KubectlLoginLogLevelEnvVar, "info")
	t.Setenv(config.IdsecLogLevelEnvVar, "debug")
	if KubectlLoginLogLevelEnabled(KubectlLoginLogLevelDebug) {
		t.Fatal("expected DEBUG disabled at private INFO level")
	}
	if !KubectlLoginLogLevelEnabled(KubectlLoginLogLevelInfo) {
		t.Fatal("expected INFO enabled at private INFO level")
	}
}

func TestKubectlLoginEffectiveLogLevel(t *testing.T) {
	setOrUnsetEnv(t, KubectlLoginLogLevelEnvVar, strPtr("info"))
	_ = os.Setenv(config.IdsecLogLevelEnvVar, "error")

	if got := KubectlLoginEffectiveLogLevel(); got != KubectlLoginLogLevelInfo {
		t.Fatalf("expected KUBELOGIN level info, got %v", got)
	}

	_ = os.Unsetenv(KubectlLoginLogLevelEnvVar)
	if got := KubectlLoginEffectiveLogLevel(); got != KubectlLoginLogLevelDebug {
		t.Fatalf("expected DEBUG default when KUBELOGIN unset, got %v", got)
	}

	t.Setenv(KubectlLoginLogLevelEnvVar, "debug")
	if got := KubectlLoginEffectiveLogLevel(); got != KubectlLoginLogLevelDebug {
		t.Fatalf("expected debug from KUBELOGIN, got %v", got)
	}

	t.Setenv(KubectlLoginLogLevelEnvVar, "   ")
	if got := KubectlLoginEffectiveLogLevel(); got != KubectlLoginLogLevelDebug {
		t.Fatalf("expected DEBUG default when KUBELOGIN blank, got %v", got)
	}

	t.Setenv(KubectlLoginLogLevelEnvVar, "CRITICAL")
	if got := KubectlLoginEffectiveLogLevel(); got != KubectlLoginLogLevelDebug {
		t.Fatalf("expected CRITICAL on KUBELOGIN ignored with DEBUG default, got %v", got)
	}
}

func strPtr(s string) *string { return &s }

// setOrUnsetEnv sets key to *value, or unsets it when value is nil, restoring the
// original state after the test. restoreEnv is defined in the package test suite.
func setOrUnsetEnv(t *testing.T, key string, value *string) {
	t.Helper()
	orig, had := os.LookupEnv(key)
	t.Cleanup(func() { restoreEnv(key, orig, had) })
	if value == nil {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, *value)
}
