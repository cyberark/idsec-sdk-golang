// Package config provides shared utilities and types for the IDSEC SDK.
//
// This package handles configuration for colored output, interactive mode, certificate
// verification, output control, logging levels, and trusted certificates. It provides
// a centralized way to control various system behaviors through global state and
// environment variables.
package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	browser "github.com/EDDYCJY/fake-useragent"
	"github.com/google/uuid"
)

var (
	// gitCommit is the commit hash of the Idsec CLI application.
	gitCommit = "N/A"

	// gitBranch is the git branch of the Idsec CLI application.
	gitBranch = "N/A"

	// buildDate is the build date of the Idsec CLI application.
	buildDate = "N/A"

	// version is the version of the Idsec CLI application.
	version = "0.0.0"

	// buildNumber is the build number of the Idsec CLI application.
	buildNumber = "0"

	// repoPath is the repository path for the Idsec CLI application.
	repoPath = "cyberark/idsec-sdk-golang"
)

func init() {
	// If version is still the default value, try to read from VERSION file
	// This handles cases where the binary wasn't built with ldflags
	if version == "0.0.0" {
		if v := readVersionFile(); v != "" {
			version = v
		}
	}
}

// readVersionFile attempts to read the VERSION file from the repository root using os.Root for security.
func readVersionFile() string {
	// Get the directory of this source file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	// Navigate up to find the repository root
	// From pkg/config/idsec_system_config.go to root: ../../
	dir := filepath.Dir(filename)
	repoRoot := filepath.Join(dir, "..", "..")

	// Clean the path to get absolute path
	repoRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return ""
	}

	// Use os.OpenRoot to scope file access under the repository root (prevents directory traversal)
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		return ""
	}
	defer func() { _ = root.Close() }()

	// Open VERSION file using the scoped root
	file, err := root.Open("VERSION")
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// IdsecTool represents the current Idsec tool in use (SDK, CLI, or Terraform Provider).
type IdsecTool string

// List of supported Idsec tools, will be set on the system config and used in different places
const (
	IdsecToolSDK               IdsecTool = "Idsec-SDK-Golang"
	IdsecToolCLI               IdsecTool = "Idsec-CLI-Golang"
	IdsecToolTerraformProvider IdsecTool = "Idsec-Terraform-Provider"
)

var (
	noColor                   = false
	isInteractive             = true
	isCertificateVerification = true
	isAllowingOutput          = false
	trustedCert               = ""
	trustedCaCertsBundlePath  = ""
	currentTool               = IdsecToolSDK
	currentCorrelationID      = ""
	isCollectionTelemetry     = true
	proxyAddress              = ""
	proxyUsername             = ""
	proxyPassword             = ""
)

const (
	// IdsecDisableCertificateVerificationEnvVar is the environment variable name for disabling certificate validation.
	//
	// When this environment variable is set to any non-empty value, certificate verification
	// will be disabled regardless of the internal isCertificateVerification setting.
	IdsecDisableCertificateVerificationEnvVar = "IDSEC_DISABLE_CERTIFICATE_VERIFICATION"

	// IdsecDisableTelemetryCollectionEnvVar is the environment variable name for disabling telemetry data collection.
	//
	// When this environment variable is set to any non-empty value, telemetry data collection
	// will be disabled regardless of the internal isCollectionTelemetry setting.
	IdsecDisableTelemetryCollectionEnvVar = "IDSEC_DISABLE_TELEMETRY_COLLECTION"

	// IdsecLoggerStyleEnvVar sets the style of the logger output.
	IdsecLoggerStyleEnvVar = "IDSEC_LOGGER_STYLE"

	// IdsecLogLevelEnvVar sets the stdout logging verbosity level.
	// Supported levels are DEBUG, INFO, WARNING, ERROR, and CRITICAL.
	IdsecLogLevelEnvVar = "IDSEC_LOG_LEVEL"

	// IdsecFileLogPathEnvVar overrides the file path used for file-based logging.
	// When unset, defaults to $HOME/.idsec/logs/idsec-cli.log.
	IdsecFileLogPathEnvVar = "IDSEC_FILE_LOG_PATH"

	// IdsecFileLogLevelEnvVar sets the verbosity level used for file-based logging output.
	// When unset, defaults to INFO.
	// Set to "none" or "off" to disable file logging entirely.
	IdsecFileLogLevelEnvVar = "IDSEC_FILE_LOG_LEVEL"

	// IdsecExtraTrustedCAPathEnvVar sets the path to an extra trusted CA certificates bundle.
	IdsecExtraTrustedCACertsBundlePathEnvVar = "IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH"

	// IdsecProxyAddressEnvVar is the environment variable name for setting the proxy address.
	// When this environment variable is set, it will be used as the proxy address for network connections
	// if no proxy address is explicitly set in the SDK configuration.
	// Note that if a proxy address is set in the SDK configuration, it will take precedence over this environment variable.
	// If nothing is set, the default environment variable settings will be used (HTTP_PROXY, HTTPS_PROXY, NO_PROXY).
	IdsecProxyAddressEnvVar = "IDSEC_PROXY_ADDRESS"

	// IdsecProxyUsernameEnvVar is the environment variable name for setting the proxy username.
	IdsecProxyUsernameEnvVar = "IDSEC_PROXY_USERNAME"

	// IdsecProxyPasswordEnvVar is the environment variable name for setting the proxy password.
	IdsecProxyPasswordEnvVar = "IDSEC_PROXY_PASSWORD" // #nosec G101
)

// DisableColor disables colored output in the console.
//
// DisableColor sets the global noColor flag to true, which will cause IsColoring()
// to return false. This affects all subsequent console output that checks for
// color support throughout the application.
//
// Example:
//
//	DisableColor()
//	if IsColoring() {
//	    // This block will not execute
//	}
func DisableColor() {
	noColor = true
}

// EnableColor enables colored output in the console.
//
// EnableColor sets the global noColor flag to false, which will cause IsColoring()
// to return true. This enables colored console output throughout the application.
//
// Example:
//
//	EnableColor()
//	if IsColoring() {
//	    // This block will execute, allowing colored output
//	}
func EnableColor() {
	noColor = false
}

// IsColoring checks if colored output is enabled.
//
// IsColoring returns true when colored output is enabled (noColor is false) and
// false when colored output is disabled. This function is used throughout the
// application to determine whether to apply color formatting to console output.
//
// Returns true if colored output is enabled, false otherwise.
//
// Example:
//
//	if IsColoring() {
//	    fmt.Print("\033[31mRed text\033[0m")
//	} else {
//	    fmt.Print("Plain text")
//	}
func IsColoring() bool {
	return !noColor
}

// EnableInteractive enables interactive mode.
//
// EnableInteractive sets the global isInteractive flag to true, allowing the
// application to prompt for user input and display interactive elements.
//
// Example:
//
//	EnableInteractive()
//	if IsInteractive() {
//	    // Show interactive prompts
//	}
func EnableInteractive() {
	isInteractive = true
}

// DisableInteractive disables interactive mode.
//
// DisableInteractive sets the global isInteractive flag to false, preventing
// the application from displaying interactive prompts or requiring user input.
// This is useful for automated scripts or CI/CD environments.
//
// Example:
//
//	DisableInteractive()
//	if IsInteractive() {
//	    // This block will not execute
//	}
func DisableInteractive() {
	isInteractive = false
}

// IsInteractive checks if interactive mode is enabled.
//
// IsInteractive returns true when the application is allowed to display
// interactive prompts and request user input, and false when running in
// non-interactive mode (suitable for automation).
//
// Returns true if interactive mode is enabled, false otherwise.
//
// Example:
//
//	if IsInteractive() {
//	    response := promptUser("Continue? (y/n): ")
//	}
func IsInteractive() bool {
	return isInteractive
}

// AllowOutput allows output to be displayed.
//
// AllowOutput sets the global isAllowingOutput flag to true, enabling the
// application to display output messages, logs, and other information to
// the console or other output destinations.
//
// Example:
//
//	AllowOutput()
//	if IsAllowingOutput() {
//	    fmt.Println("This message will be displayed")
//	}
func AllowOutput() {
	isAllowingOutput = true
}

// DisallowOutput disallows output to be displayed.
//
// DisallowOutput sets the global isAllowingOutput flag to false, preventing
// the application from displaying output. This is useful for silent operation
// modes or when output needs to be suppressed.
//
// Example:
//
//	DisallowOutput()
//	if IsAllowingOutput() {
//	    // This block will not execute
//	}
func DisallowOutput() {
	isAllowingOutput = false
}

// IsAllowingOutput checks if output is allowed to be displayed.
//
// IsAllowingOutput returns true when the application is permitted to display
// output messages and false when output should be suppressed.
//
// Returns true if output is allowed, false otherwise.
//
// Example:
//
//	if IsAllowingOutput() {
//	    logger.Info("Operation completed successfully")
//	}
func IsAllowingOutput() bool {
	return isAllowingOutput
}

// EnableVerboseLogging enables verbose logging with the specified log level.
//
// EnableVerboseLogging sets the IdsecLogLevelEnvVar environment variable to the provided
// log level string. If an empty string is provided, it defaults to "DEBUG".
// This affects the logging verbosity throughout the application.
//
// Parameters:
//   - logLevel: The desired log level string (defaults to "DEBUG" if empty)
//
// Example:
//
//	EnableVerboseLogging("INFO")
//	EnableVerboseLogging("") // Uses "DEBUG" as default
func EnableVerboseLogging(logLevel string) {
	if logLevel == "" {
		logLevel = "DEBUG"
	}
	_ = os.Setenv(IdsecLogLevelEnvVar, logLevel)
}

// DisableVerboseLogging disables verbose logging.
//
// DisableVerboseLogging sets the IdsecLogLevelEnvVar environment variable to "CRITICAL",
// effectively reducing the logging output to only critical messages.
//
// Example:
//
//	DisableVerboseLogging()
//	// Only critical log messages will be displayed
func DisableVerboseLogging() {
	_ = os.Setenv(IdsecLogLevelEnvVar, "CRITICAL")
}

// SetLoggerStyle sets the logger style based on the provided string.
//
// SetLoggerStyle configures the IdsecLoggerStyleEnvVar environment variable. If the
// provided style is "default", it sets the style to "default"; otherwise,
// it defaults to "default" regardless of the input value.
//
// Parameters:
//   - loggerStyle: The desired logger style ("default" or any other value defaults to "default")
//
// Example:
//
//	SetLoggerStyle("default")
//	SetLoggerStyle("custom") // Also sets to "default"
func SetLoggerStyle(loggerStyle string) {
	if loggerStyle == "default" {
		_ = os.Setenv(IdsecLoggerStyleEnvVar, loggerStyle)
	} else {
		_ = os.Setenv(IdsecLoggerStyleEnvVar, "default")
	}
}

// EnableCertificateVerification enables certificate verification.
//
// EnableCertificateVerification sets the global isCertificateVerification flag
// to true, enabling SSL/TLS certificate validation for network connections.
// Note that if the IdsecDisableCertificateVerificationEnvVar environment variable
// is set, certificate verification will still be disabled.
//
// Example:
//
//	EnableCertificateVerification()
//	if IsVerifyingCertificates() {
//	    // Certificates will be verified
//	}
func EnableCertificateVerification() {
	isCertificateVerification = true
}

// DisableCertificateVerification disables certificate verification.
//
// DisableCertificateVerification sets the global isCertificateVerification flag
// to false, disabling SSL/TLS certificate validation for network connections.
// This should be used with caution as it reduces security.
//
// Example:
//
//	DisableCertificateVerification()
//	if IsVerifyingCertificates() {
//	    // This block will not execute
//	}
func DisableCertificateVerification() {
	isCertificateVerification = false
}

// IsVerifyingCertificates checks if certificate verification is enabled.
//
// IsVerifyingCertificates returns false if the IdsecDisableCertificateVerificationEnvVar
// environment variable is set to any non-empty value, regardless of the internal
// isCertificateVerification setting. Otherwise, it returns the value of the
// isCertificateVerification flag.
//
// Returns true if certificate verification is enabled, false otherwise.
//
// Example:
//
//	if IsVerifyingCertificates() {
//	    // Use secure connection with certificate validation
//	} else {
//	    // Use connection without certificate validation
//	}
func IsVerifyingCertificates() bool {
	if os.Getenv(IdsecDisableCertificateVerificationEnvVar) != "" {
		return false
	}
	return isCertificateVerification
}

// SetTrustedCertificate sets the trusted certificate for verification.
//
// SetTrustedCertificate stores the provided certificate string in the global
// trustedCert variable. This certificate can be used for custom certificate
// validation scenarios.
//
// Parameters:
//   - cert: The certificate string to be stored as trusted
//
// Example:
//
//	cert := "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
//	SetTrustedCertificate(cert)
func SetTrustedCertificate(cert string) {
	trustedCert = cert
}

// TrustedCertificate returns the trusted certificate for verification.
//
// TrustedCertificate retrieves the currently stored trusted certificate string
// that was previously set using SetTrustedCertificate. Returns an empty string
// if no certificate has been set.
//
// Returns the trusted certificate string, or empty string if none is set.
//
// Example:
//
//	cert := TrustedCertificate()
//	if cert != "" {
//	    // Use the trusted certificate for validation
//	}
func TrustedCertificate() string {
	return trustedCert
}

// SetExtraTrustedCACertsBundlePath sets the path to an extra trusted CA certificates bundle.
//
// SetExtraTrustedCACertsBundlePath stores the provided file path in the global
// trustedCaCertsBundlePath variable. This path can be used to load additional
// trusted CA certificates for SSL/TLS verification.
//
// Parameters:
//   - path: The file path to the extra trusted CA certificates bundle
//
// Example:
//
//	path := "/path/to/extra_ca_certs.pem"
//	SetExtraTrustedCACertsBundlePath(path)
func SetExtraTrustedCACertsBundlePath(path string) {
	trustedCaCertsBundlePath = path
}

// ExtraTrustedCACertsBundlePath returns the path to an extra trusted CA certificates bundle.
//
// ExtraTrustedCACertsBundlePath retrieves the currently stored file path for
// the extra trusted CA certificates bundle that was previously set using
// SetExtraTrustedCACertsBundlePath. If no path has been set, it checks the
// IdsecExtraTrustedCACertsBundlePathEnvVar environment variable.
//
// Returns the file path to the extra trusted CA certificates bundle.
//
// Example:
//
//	path := ExtraTrustedCACertsBundlePath()
//	if path != "" {
//	    // Load extra trusted CA certificates from the specified path
//	}
func ExtraTrustedCACertsBundlePath() string {
	if trustedCaCertsBundlePath != "" {
		return trustedCaCertsBundlePath
	}
	return os.Getenv(IdsecExtraTrustedCACertsBundlePathEnvVar)
}

// SetProxyAddress sets the proxy address for network connections.
// SetProxyAddress stores the provided address string in the global
// proxyAddress variable. This address can be used for configuring proxy
// settings for network connections.
//
// Parameters:
//   - address: The proxy address string to be stored
//
// Example:
//
//	address := "http://proxy.example.com:8080"
//	SetProxyAddress(address)
func SetProxyAddress(address string) {
	proxyAddress = address
}

// ProxyAddress returns the proxy address for network connections.
//
// ProxyAddress retrieves the currently stored proxy address string
// that was previously set using SetProxyAddress. Returns an empty string
// if no address has been set.
//
// Returns the proxy address string, or empty string if none is set.
//
// Example:
//
//	address := ProxyAddress()
//	if address != "" {
//	    // Use the proxy address for network connections
//	}
func ProxyAddress() string {
	if proxyAddress != "" {
		return proxyAddress
	}
	return os.Getenv(IdsecProxyAddressEnvVar)
}

// SetProxyUsername sets the proxy username for network connections.
// SetProxyUsername stores the provided username string in the global
// proxyUsername variable. This username can be used for configuring proxy
// authentication for network connections.
//
// Parameters:
//   - username: The proxy username string to be stored
//
// Example:
//
//	username := "proxyuser"
//	SetProxyUsername(username)
func SetProxyUsername(username string) {
	proxyUsername = username
}

// ProxyUsername returns the proxy username for network connections.
//
// ProxyUsername retrieves the currently stored proxy username string
// that was previously set using SetProxyUsername. Returns an empty string
// if no username has been set.
//
// Returns the proxy username string, or empty string if none is set.
//
// Example:
//
//	username := ProxyUsername()
//	if username != "" {
//	    // Use the proxy username for network connections
//	}
func ProxyUsername() string {
	if proxyUsername != "" {
		return proxyUsername
	}
	return os.Getenv(IdsecProxyUsernameEnvVar)
}

// SetProxyPassword sets the proxy password for network connections.
// SetProxyPassword stores the provided password string in the global
// proxyPassword variable. This password can be used for configuring proxy
// authentication for network connections.
//
// Parameters:
//   - password: The proxy password string to be stored
//
// Example:
//
//	password := "proxypassword"
//	SetProxyPassword(password)
func SetProxyPassword(password string) {
	proxyPassword = password
}

// ProxyPassword returns the proxy password for network connections.
//
// ProxyPassword retrieves the currently stored proxy password string
// that was previously set using SetProxyPassword. Returns an empty string
// if no password has been set.
//
// Returns the proxy password string, or empty string if none is set.
//
// Example:
//
//	password := ProxyPassword()
//	if password != "" {
//	    // Use the proxy password for network connections
//	}
func ProxyPassword() string {
	if proxyPassword != "" {
		return proxyPassword
	}
	return os.Getenv(IdsecProxyPasswordEnvVar)
}

// DisableTelemetryCollection disables telemetry data collection.
//
// DisableTelemetryCollection sets the global isCollectionTelemetry flag to false,
// preventing the application from collecting and sending telemetry data.
//
// Example:
//
//	DisableTelemetryCollection()
//	if IsTelemetryCollectionEnabled() {
//	    // This block will not execute
//	}
func DisableTelemetryCollection() {
	isCollectionTelemetry = false
}

// EnableTelemetryCollection enables telemetry data collection.
//
// EnableTelemetryCollection sets the global isCollectionTelemetry flag to true,
// allowing the application to collect and send telemetry data.
//
// Example:
//
//	EnableTelemetryCollection()
//	if IsTelemetryCollectionEnabled() {
//	    // Telemetry data will be collected
//	}
func EnableTelemetryCollection() {
	isCollectionTelemetry = true
}

// IsTelemetryCollectionEnabled checks if telemetry data collection is enabled.
//
// IsTelemetryCollectionEnabled returns false if the IdsecDisableTelemetryCollectionEnvVar
// environment variable is set to any non-empty value, regardless of the internal
// isCollectionTelemetry setting. Otherwise, it returns the value of the
// isCollectionTelemetry flag.
//
// Returns true if telemetry data collection is enabled, false otherwise.
//
// Example:
//
//	if IsTelemetryCollectionEnabled() {
//	    // Collect and send telemetry data
//	}
func IsTelemetryCollectionEnabled() bool {
	if os.Getenv(IdsecDisableTelemetryCollectionEnvVar) != "" {
		return false
	}
	return isCollectionTelemetry
}

// IdsecPath returns the module path of the Idsec SDK.
//
// IdsecPath retrieves the module path string for the Idsec SDK, which is
// "cyberark/idsec-sdk-golang" by default.
func IdsecPath() string {
	return repoPath
}

// SetIdsecPath sets the module path of the Idsec SDK for testing purposes.
func SetIdsecPath(path string) {
	if path != "" {
		repoPath = path
	}
}

// IdsecVersion returns the current version of the Idsec SDK.
//
// IdsecVersion retrieves the currently stored SDK version string. The default
// version is "0.0.0" if no version has been explicitly set using SetIdsecVersion.
//
// Returns the current SDK version string.
//
// Example:
//
//	version := IdsecVersion()
//	fmt.Printf("Current SDK version: %s\n", version)
func IdsecVersion() string {
	return version
}

// SetIdsecVersion sets the current version of the Idsec SDK for testing purposes.
func SetIdsecVersion(v string) {
	if v != "" {
		version = v
	}
}

// IdsecBuildNumber returns the build number of the Idsec SDK.
//
// IdsecBuildNumber retrieves the build number string for the Idsec SDK,
// which is "0" by default.
func IdsecBuildNumber() string {
	return buildNumber
}

// SetIdsecBuildNumber sets the build number of the Idsec SDK for testing purposes.
func SetIdsecBuildNumber(bn string) {
	if bn != "" {
		buildNumber = bn
	}
}

// IdsecBuildDate returns the build date of the Idsec SDK.
//
// IdsecBuildDate retrieves the build date string for the Idsec SDK,
// which is "N/A" by default.
func IdsecBuildDate() string {
	return buildDate
}

// SetIdsecBuildDate sets the build date of the Idsec SDK for testing purposes.
func SetIdsecBuildDate(bd string) {
	if bd != "" {
		buildDate = bd
	}
}

// IdsecGitCommit returns the git commit hash of the Idsec SDK.
//
// IdsecGitCommit retrieves the git commit hash string for the Idsec SDK,
// which is "N/A" by default.
func IdsecGitCommit() string {
	return gitCommit
}

// SetIdsecGitCommit sets the git commit hash of the Idsec SDK for testing purposes.
func SetIdsecGitCommit(gc string) {
	if gc != "" {
		gitCommit = gc
	}
}

// IdsecGitBranch returns the git branch of the Idsec SDK.
//
// IdsecGitBranch retrieves the git branch string for the Idsec SDK,
// which is "N/A" by default.
func IdsecGitBranch() string {
	return gitBranch
}

// SetIdsecGitBranch sets the git branch of the Idsec SDK for testing purposes.
func SetIdsecGitBranch(gb string) {
	if gb != "" {
		gitBranch = gb
	}
}

// IdsecToolInUse returns the current Idsec tool in use.
//
// IdsecToolInUse retrieves the value of the global currentTool variable, indicating
// which Idsec tool (SDK, CLI, or Terraform Provider) is currently being used.
//
// Returns the IdsecTool value representing the current tool in use.
//
// Example:
//
//	fmt.Println(IdsecToolInUse()) // Outputs: Idsec-SDK-Golang
func IdsecToolInUse() IdsecTool {
	return currentTool
}

// SetIdsecToolInUse sets the current Idsec tool in use.
//
// SetIdsecToolInUse updates the global currentTool variable to the provided IdsecTool
// value. This indicates which Idsec tool (SDK, CLI, or Terraform Provider) is
// currently being used.
//
// Parameters:
//   - tool: The IdsecTool value representing the current tool in use
//
// Example:
//
//	SetIdsecToolInUse(IdsecToolCLI)
//	fmt.Println(IdsecToolInUse()) // Outputs: Idsec-CLI-Golang
func SetIdsecToolInUse(tool IdsecTool) {
	currentTool = tool
}

// GenerateCorrelationID generates a new correlation ID.
//
// GenerateCorrelationID creates a new UUID and assigns it to the global
// currentCorrelationID variable. It returns the newly generated correlation ID
// as a string.
//
// Returns the newly generated correlation ID string.
//
// Example:
//
//	correlationID := GenerateCorrelationID()
//	fmt.Println(correlationID) // Outputs a new UUID string
func GenerateCorrelationID() string {
	currentCorrelationID = uuid.New().String()
	return currentCorrelationID
}

// CorrelationID returns the current correlation ID.
//
// CorrelationID retrieves the value of the global currentCorrelationID variable.
// If no correlation ID has been set, it generates a new one using
// GenerateCorrelationID and returns that value.
//
// Returns the current correlation ID string.
//
// Example:
//
//	correlationID := CorrelationID()
//	fmt.Println(correlationID) // Outputs the current or newly generated UUID string
func CorrelationID() string {
	if currentCorrelationID == "" {
		return GenerateCorrelationID()
	}
	return currentCorrelationID
}

// UserAgent returns the user agent string for the Idsec SDK in Golang.
//
// UserAgent generates a composite user agent string by combining a Chrome browser
// user agent (obtained from the fake-useragent library) with the current IDSEC SDK
// version. This provides proper identification for HTTP requests made by the SDK
// while maintaining compatibility with web services that expect browser-like
// user agents.
//
// Returns a formatted user agent string in the format:
// "{Chrome User Agent} Idsec-SDK-Golang/{version}"
//
// Example:
//
//	userAgent := UserAgent()
//	// userAgent might be:
//	// "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Idsec-SDK-Golang/1.2.3"
func UserAgent() string {
	return browser.Chrome() + fmt.Sprintf(" %s/%s", IdsecToolInUse(), IdsecVersion())
}
