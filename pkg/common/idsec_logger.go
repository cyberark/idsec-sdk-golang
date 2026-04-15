// Package common provides shared utilities and types for the IDSEC SDK.
//
// This package implements a custom logger with configurable log levels,
// color-coded output, and environment variable support for configuration.
package common

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// Log level constants for IdsecLogger.
//
// These constants define the severity levels used by the logging system.
// Higher numbers indicate more verbose output (Debug=4 is most verbose,
// Critical=0 is least verbose).
const (
	Debug    = 4
	Info     = 3
	Warning  = 2
	Error    = 1
	Critical = 0
	Unknown  = -1
)

const (
	// LoggerStyleDefault is the default logger style
	LoggerStyleDefault = "default"

	defaultLogRotationMaxSizeBytes   = int64(50 * 1024 * 1024) // 50 MB
	defaultLogRotationBackupHistory  = 5
	defaultLogRotationStatCheckBytes = int64(1 * 1024 * 1024) // 1 MB
	defaultFileLogLevel              = Info
	defaultFileLogDir                = ".idsec/logs"
	defaultFileLogName               = "idsec-cli.log"
)

// IdsecLogger provides structured logging with configurable levels and output formatting.
//
// IdsecLogger wraps the standard log.Logger and adds features like:
// - Configurable log levels (Debug, Info, Warning, Error, Critical)
// - Color-coded console output
// - Environment variable configuration
// - Verbose mode control
//
// The logger supports both static configuration and dynamic environment-based
// configuration for flexible deployment scenarios.
type IdsecLogger struct {
	*log.Logger
	verbose                bool
	logLevel               int
	name                   string
	resolveLogLevelFromEnv bool
	fileOutput             io.Writer
	fileLogLevel           int
	isFileLoggingEnabled   bool
	fileLoggingResolved    bool
}

// NewIdsecLogger creates a new instance of IdsecLogger with the specified configuration.
//
// This function initializes a new logger with the provided settings. The logger
// will output to stdout with timestamp formatting and can be configured for
// different verbosity levels and environment-based configuration.
//
// Parameters:
//   - name: The name/prefix for log messages
//   - level: The minimum log level (0=Critical, 1=Error, 2=Warning, 3=Info, 4=Debug)
//   - verbose: Whether to enable verbose output (false disables all logging)
//   - resolveLogLevelFromEnv: Whether to dynamically resolve log level from LOG_LEVEL env var
//
// Returns a configured IdsecLogger instance ready for use.
//
// Example:
//
//	logger := NewIdsecLogger("myapp", Info, true, false)
//	logger.Info("Application started")
func NewIdsecLogger(name string, level int, verbose bool, resolveLogLevelFromEnv bool) *IdsecLogger {
	return &IdsecLogger{
		Logger:                 log.New(os.Stdout, name, log.LstdFlags),
		name:                   name,
		verbose:                verbose,
		logLevel:               level,
		resolveLogLevelFromEnv: resolveLogLevelFromEnv,
	}
}

// isFileLoggingExplicitlyDisabled checks if file logging was disabled by env value.
func isFileLoggingExplicitlyDisabled(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v == "none" || v == "off"
}

// resolveFileLoggingConfig resolves file writer config for CLI-only file logging.
func resolveFileLoggingConfig() (io.Writer, int, bool) {
	// File logging is intentionally available only for CLI executions.
	if config.IdsecToolInUse() != config.IdsecToolCLI {
		return nil, Critical, false
	}
	rawLevel := os.Getenv(config.IdsecFileLogLevelEnvVar)
	if isFileLoggingExplicitlyDisabled(rawLevel) {
		return nil, Critical, false
	}
	rawPath := os.Getenv(config.IdsecFileLogPathEnvVar)
	filePath := strings.TrimSpace(rawPath)
	if filePath == "" {
		filePath = defaultFileLogPath()
	}
	if filePath == "" {
		return nil, Critical, false
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return nil, Critical, false
	}
	fileLogLevel := resolveFileLogLevelFromEnv()
	return &rotatingFileWriter{
		filePath:          filePath,
		maxSizeBytes:      defaultLogRotationMaxSizeBytes,
		maxBackups:        defaultLogRotationBackupHistory,
		statCheckInterval: defaultLogRotationStatCheckBytes,
	}, fileLogLevel, true
}

// defaultFileLogPath resolves the default CLI file log path in the user home directory.
func defaultFileLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, defaultFileLogDir, defaultFileLogName)
}

// resolveFileLogLevelFromEnv resolves the file log level from env with INFO default.
func resolveFileLogLevelFromEnv() int {
	fileLogLevel := strings.TrimSpace(os.Getenv(config.IdsecFileLogLevelEnvVar))
	if fileLogLevel == "" {
		return defaultFileLogLevel
	}
	return StrToLogLevel(fileLogLevel)
}

type rotatingFileWriter struct {
	mu                 sync.Mutex
	filePath           string
	maxSizeBytes       int64
	maxBackups         int
	bytesSinceLastStat int64
	statCheckInterval  int64
}

// Write appends to the log file and checks rotation periodically.
func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(w.filePath), 0o700); err != nil {
		return 0, err
	}

	w.bytesSinceLastStat += int64(len(p))
	if w.bytesSinceLastStat >= w.statCheckInterval {
		w.bytesSinceLastStat = 0
		if err := w.rotateIfNeeded(); err != nil {
			return 0, err
		}
	}

	file, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	return file.Write(p)
}

// rotateIfNeeded stats the file and triggers rotation if it exceeds max size.
func (w *rotatingFileWriter) rotateIfNeeded() error {
	fileInfo, err := os.Stat(w.filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if fileInfo.Size() <= w.maxSizeBytes {
		return nil
	}
	return w.rotate()
}

// rotate shifts backups and rotates the current log file to .1.
func (w *rotatingFileWriter) rotate() error {
	if w.maxBackups < 1 {
		return os.Remove(w.filePath)
	}
	oldestFilePath := fmt.Sprintf("%s.%d", w.filePath, w.maxBackups)
	if err := os.Remove(oldestFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := w.maxBackups - 1; i >= 1; i-- {
		sourcePath := fmt.Sprintf("%s.%d", w.filePath, i)
		targetPath := fmt.Sprintf("%s.%d", w.filePath, i+1)
		if err := os.Rename(sourcePath, targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	rotatedPath := fmt.Sprintf("%s.1", w.filePath)
	if err := os.Rename(w.filePath, rotatedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// LogLevelFromEnv retrieves the log level from the LOG_LEVEL environment variable.
//
// This function reads the LOG_LEVEL environment variable and converts it to
// the corresponding integer log level. If the environment variable is not set
// or empty, it defaults to Critical level.
//
// Returns the integer log level corresponding to the environment variable value,
// or Critical (0) if the variable is not set or contains an invalid value.
//
// Example:
//
//	os.Setenv("LOG_LEVEL", "DEBUG")
//	level := LogLevelFromEnv() // Returns 4 (Debug)
func LogLevelFromEnv() int {
	logLevelStr := os.Getenv(config.IdsecLogLevelEnvVar)
	if logLevelStr == "" {
		return Critical
	}
	return StrToLogLevel(logLevelStr)
}

// StrToLogLevel converts a string representation of a log level to its integer value.
//
// This function parses string log level names (case-insensitive) and returns
// the corresponding integer constant. Supported values are DEBUG, INFO, WARNING,
// ERROR, and CRITICAL. Any unrecognized value defaults to Critical.
//
// Parameters:
//   - logLevelStr: String representation of the log level (e.g., "DEBUG", "info", "Warning")
//
// Returns the integer constant corresponding to the log level, or Critical (0)
// for unrecognized input.
//
// Example:
//
//	level := StrToLogLevel("DEBUG")    // Returns 4
//	level := StrToLogLevel("invalid")  // Returns 0 (Critical)
func StrToLogLevel(logLevelStr string) int {
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		return Debug
	case "INFO":
		return Info
	case "WARNING":
		return Warning
	case "ERROR":
		return Error
	case "CRITICAL":
		return Critical
	default:
		return Critical
	}
}

// LogLevel returns the current effective log level of the logger.
//
// This method returns the log level that will be used for filtering log messages.
// If the logger is configured to resolve the level from environment variables,
// it will dynamically read the LOG_LEVEL environment variable. Otherwise,
// it returns the static log level set during logger creation.
//
// Returns the current log level as an integer (0=Critical, 1=Error, 2=Warning, 3=Info, 4=Debug).
func (l *IdsecLogger) LogLevel() int {
	if l.resolveLogLevelFromEnv {
		return LogLevelFromEnv()
	}
	return l.logLevel
}

// SetVerbose sets the verbosity mode of the logger.
//
// When verbose is false, the logger will not output any messages regardless
// of the log level. This provides a master switch to disable all logging
// output from the logger instance.
//
// Parameters:
//   - value: true to enable verbose output, false to disable all output
func (l *IdsecLogger) SetVerbose(value bool) {
	l.verbose = value
}

// ensureFileLoggingResolved lazily resolves file logging once per logger instance.
func (l *IdsecLogger) ensureFileLoggingResolved() {
	if l.fileLoggingResolved {
		return
	}
	l.fileLoggingResolved = true
	l.fileOutput, l.fileLogLevel, l.isFileLoggingEnabled = resolveFileLoggingConfig()
}

// logToFile writes one sanitized log line to file if file logging is enabled.
func (l *IdsecLogger) logToFile(level int, levelName string, message string) {
	l.ensureFileLoggingResolved()
	if !l.isFileLoggingEnabled || l.fileOutput == nil {
		return
	}
	if l.fileLogLevel < level {
		return
	}
	logLine := fmt.Sprintf(
		"%s | %s | %s | %s\n",
		time.Now().UTC().Format(time.RFC3339),
		l.name,
		levelName,
		sanitizeMessage(message),
	)
	_, _ = l.fileOutput.Write([]byte(logLine))
}

// Debug logs a debug message with green color formatting.
//
// Debug messages are only output when the logger is in verbose mode and
// the current log level is set to Debug (4) or higher. Debug messages
// are typically used for detailed diagnostic information.
//
// Parameters:
//   - msg: Format string for the log message
//   - v: Optional format arguments for the message string
//
// Example:
//
//	logger.Debug("Processing user %s with ID %d", username, userID)
func (l *IdsecLogger) Debug(msg string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, v...)
	l.logToFile(Debug, "DEBUG", formattedMessage)
	if !l.verbose {
		return
	}
	if l.LogLevel() < Debug {
		return
	}
	colorMsg := fmt.Sprintf("| DEBUG | \033[1;32m%s\033[0m", formattedMessage)
	l.Println(colorMsg)
}

// Info logs an informational message with green color formatting.
//
// Info messages are output when the logger is in verbose mode and
// the current log level is set to Info (3) or higher. Info messages
// are used for general application flow information.
//
// Parameters:
//   - msg: Format string for the log message
//   - v: Optional format arguments for the message string
//
// Example:
//
//	logger.Info("User %s logged in successfully", username)
func (l *IdsecLogger) Info(msg string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, v...)
	l.logToFile(Info, "INFO", formattedMessage)
	if !l.verbose {
		return
	}
	if l.LogLevel() < Info {
		return
	}
	colorMsg := fmt.Sprintf("| INFO | \033[32m%s\033[0m", formattedMessage)
	l.Println(colorMsg)
}

// Warning logs a warning message with yellow color formatting.
//
// Warning messages are output when the logger is in verbose mode and
// the current log level is set to Warning (2) or higher. Warning messages
// indicate potentially problematic situations that don't prevent operation.
//
// Parameters:
//   - msg: Format string for the log message
//   - v: Optional format arguments for the message string
//
// Example:
//
//	logger.Warning("Rate limit approaching for user %s", username)
func (l *IdsecLogger) Warning(msg string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, v...)
	l.logToFile(Warning, "WARNING", formattedMessage)
	if !l.verbose {
		return
	}
	if l.LogLevel() < Warning {
		return
	}
	colorMsg := fmt.Sprintf("| WARNING | \033[33m%s\033[0m", formattedMessage)
	l.Println(colorMsg)
}

// Error logs an error message with red color formatting.
//
// Error messages are output when the logger is in verbose mode and
// the current log level is set to Error (1) or higher. Error messages
// indicate error conditions that should be investigated.
//
// Parameters:
//   - msg: Format string for the log message
//   - v: Optional format arguments for the message string
//
// Example:
//
//	logger.Error("Failed to connect to database: %v", err)
func (l *IdsecLogger) Error(msg string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, v...)
	l.logToFile(Error, "ERROR", formattedMessage)
	if !l.verbose {
		return
	}
	if l.LogLevel() < Error {
		return
	}
	colorMsg := fmt.Sprintf("| ERROR | \033[31m%s\033[0m", formattedMessage)
	l.Println(colorMsg)
}

// Fatal logs a fatal error message with bright red color formatting and exits the program.
//
// Fatal messages are output when the logger is in verbose mode and
// the current log level is set to Critical (0) or higher. After logging
// the message, this method calls os.Exit(-1) to terminate the program.
// This should only be used for unrecoverable error conditions.
//
// Parameters:
//   - msg: Format string for the log message
//   - v: Optional format arguments for the message string
//
// Example:
//
//	logger.Fatal("Cannot start application: %v", err)
//	// Program terminates after this call
func (l *IdsecLogger) Fatal(msg string, v ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, v...)
	l.logToFile(Critical, "FATAL", formattedMessage)
	if !l.verbose {
		return
	}
	if l.LogLevel() < Critical {
		return
	}
	colorMsg := fmt.Sprintf("| FATAL | \033[1;31m%s\033[0m", formattedMessage)
	l.Println(colorMsg)
	os.Exit(-1)
}

// GetLogger creates a new instance of IdsecLogger with application-specific configuration.
//
// This is the primary factory function for creating logger instances. It handles
// environment variable resolution, logger style configuration, and sets up
// appropriate formatting. If logLevel is -1, the logger will dynamically
// resolve the log level from the LOG_LEVEL environment variable.
//
// Parameters:
//   - app: Application name used as the logger prefix
//   - logLevel: Static log level (0-4), or -1 to resolve from environment
//
// Returns a configured IdsecLogger instance, or nil if an unsupported logger
// style is specified in the LOGGER_STYLE environment variable.
//
// Example:
//
//	logger := GetLogger("myapp", Info)        // Static Info level
//	envLogger := GetLogger("myapp", -1)       // Dynamic level from env
func GetLogger(app string, logLevel int) *IdsecLogger {
	resolveLogLevelFromEnv := false
	if logLevel == -1 {
		resolveLogLevelFromEnv = true
		logLevel = LogLevelFromEnv()
	}
	envLoggerStyle := os.Getenv(config.IdsecLoggerStyleEnvVar)
	if envLoggerStyle == "" {
		envLoggerStyle = LoggerStyleDefault
	}
	loggerStyle := strings.ToLower(envLoggerStyle)
	if loggerStyle == LoggerStyleDefault {
		logFormat := "%s | "
		logger := NewIdsecLogger(app, logLevel, true, resolveLogLevelFromEnv)
		logger.SetFlags(log.LstdFlags)
		logger.SetPrefix(fmt.Sprintf(logFormat, app))
		return logger
	}
	return nil
}

// GlobalLogger is the global logger instance for the Idsec SDK.
//
// This variable provides a package-level logger that can be used throughout
// the Idsec SDK. It is configured to resolve its log level from the LOG_LEVEL
// environment variable and uses "idsec-sdk" as its prefix.
//
// Example:
//
//	common.GlobalLogger.Info("SDK operation completed")
var GlobalLogger = GetLogger("idsec-sdk", -1)
