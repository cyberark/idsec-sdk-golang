package k8s

// Kubectl-login diagnostics go to stderr only (stdout is ExecCredential JSON).
//
// On/off: IDSEC_VERBOSE (CLI) or context.Diagnostics (SDK). Severity filter:
// IDSEC_KUBELOGIN_LOG_LEVEL (default DEBUG). CLI may copy IDSEC_LOG_LEVEL into
// KUBELOGIN at startup; this package reads KUBELOGIN only. SDK call sites:
// KubectlLoginLog when context.Diagnostics is true.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const KubectlLoginLogLevelEnvVar = "IDSEC_KUBELOGIN_LOG_LEVEL"

// KubectlLoginLogLevel: higher value = more verbose (ERROR .. DEBUG).
type KubectlLoginLogLevel int

const (
	KubectlLoginLogLevelError KubectlLoginLogLevel = iota + 1
	KubectlLoginLogLevelWarning
	KubectlLoginLogLevelInfo
	KubectlLoginLogLevelDebug
)

func KubectlLoginLogLevelFromString(value string) KubectlLoginLogLevel {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "DEBUG":
		return KubectlLoginLogLevelDebug
	case "INFO":
		return KubectlLoginLogLevelInfo
	case "WARNING", "WARN":
		return KubectlLoginLogLevelWarning
	case "ERROR", "CRITICAL", "FATAL":
		return KubectlLoginLogLevelError
	default:
		return KubectlLoginLogLevelDebug
	}
}

func KubectlLoginLogLevelName(level KubectlLoginLogLevel) string {
	switch level {
	case KubectlLoginLogLevelDebug:
		return "DEBUG"
	case KubectlLoginLogLevelInfo:
		return "INFO"
	case KubectlLoginLogLevelWarning:
		return "WARNING"
	case KubectlLoginLogLevelError:
		return "ERROR"
	default:
		return "DEBUG"
	}
}

// KubectlLoginEffectiveLogLevel reads IDSEC_KUBELOGIN_LOG_LEVEL; default DEBUG.
func KubectlLoginEffectiveLogLevel() KubectlLoginLogLevel {
	if level, ok := kubectlLoginLogLevelFromEnv(os.Getenv(KubectlLoginLogLevelEnvVar)); ok {
		return level
	}
	return KubectlLoginLogLevelDebug
}

func kubectlLoginLogLevelFromEnv(value string) (KubectlLoginLogLevel, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	switch strings.ToUpper(value) {
	case "CRITICAL", "FATAL":
		return 0, false
	}
	return KubectlLoginLogLevelFromString(value), true
}

func KubectlLoginLogLevelEnabled(messageLevel KubectlLoginLogLevel) bool {
	return KubectlLoginEffectiveLogLevel() >= messageLevel
}

// KubectlLoginLog applies the env severity filter; caller gates on/off.
func KubectlLoginLog(level KubectlLoginLogLevel, format string, args ...any) {
	if !KubectlLoginLogLevelEnabled(level) {
		return
	}
	KubectlLoginLogLine(os.Stderr, level, format, args...)
}

// KubectlLoginLogLine writes "kubectl-login | <time> | <LEVEL> | <msg>". Nil writer is a no-op.
func KubectlLoginLogLine(writer io.Writer, level KubectlLoginLogLevel, format string, args ...any) {
	if writer == nil {
		return
	}
	message := strings.NewReplacer("\r", " ", "\n", " ").Replace(fmt.Sprintf(format, args...))
	_, _ = fmt.Fprintf(writer, "%s | %s | %s | %s\n",
		"kubectl-login",
		time.Now().Format("2006/01/02 15:04:05"),
		KubectlLoginLogLevelName(level),
		message,
	)
}
