// Package actions provides base functionality for Idsec SDK command line actions.
//
// This package defines the core interfaces and base implementations for creating
// command line actions in the Idsec SDK. It includes configuration management,
// flag handling, and common execution patterns that can be shared across
// different CLI commands.
package actions

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	suppressUpgradeCheckEnvVar  = "IDSEC_SUPPRESS_UPGRADE_CHECK"
	versionCheckFileName        = ".last_version_check"
	versionCheckIntervalSeconds = 12 * 60 * 60
)

// IdsecAction is an interface that defines the structure for actions in the Idsec SDK.
//
// IdsecAction provides a contract for implementing command line actions that can
// be integrated with the Idsec SDK CLI framework. Implementations should define
// their specific command behavior through the DefineAction method.
type IdsecAction interface {
	// DefineAction configures the provided cobra command with action-specific behavior
	DefineAction(cmd *cobra.Command)
}

// IdsecBaseAction is a struct that implements the IdsecAction interface as a base action.
//
// IdsecBaseAction provides common functionality that can be shared across different
// action implementations. It includes logger management and common flag handling
// patterns. This struct can be embedded in more specific action implementations
// to provide consistent behavior across the CLI.
type IdsecBaseAction struct {
	// logger is the internal logger instance for the action
	logger *common.IdsecLogger
}

// NewIdsecBaseAction creates a new instance of IdsecBaseAction.
//
// NewIdsecBaseAction initializes a new IdsecBaseAction with a configured logger.
// The logger is set up with a default configuration using the "IdsecBaseAction"
// name and Unknown log level.
//
// Returns a new IdsecBaseAction instance ready for use.
//
// Example:
//
//	action := NewIdsecBaseAction()
//	action.CommonActionsConfiguration(cmd)
func NewIdsecBaseAction() *IdsecBaseAction {
	return &IdsecBaseAction{
		logger: common.GetLogger("IdsecBaseAction", common.Unknown),
	}
}

// CommonActionsConfiguration sets up common flags for the command line interface.
//
// CommonActionsConfiguration adds standard persistent flags to the provided cobra
// command that are commonly used across different Idsec SDK actions. These flags
// control logging behavior, output formatting, certificate handling, and other
// common CLI options.
//
// The following flags are added:
//   - raw: Controls whether output should be in raw format
//   - silent: Enables silent execution without interactive prompts
//   - allow-output: Allows stdout/stderr output even in silent mode
//   - verbose: Enables verbose logging
//   - logger-style: Specifies the style for verbose logging
//   - log-level: Sets the log level for verbose mode
//   - disable-cert-verification: Disables HTTPS certificate verification (unsafe)
//   - trusted-cert: Specifies a trusted certificate for HTTPS calls
//
// Parameters:
//   - cmd: The cobra command to configure with persistent flags
//
// Example:
//
//	action := NewIdsecBaseAction()
//	action.CommonActionsConfiguration(rootCmd)
func (a *IdsecBaseAction) CommonActionsConfiguration(cmd *cobra.Command) {
	cmd.PersistentFlags().Bool("raw", false, "Whether to raw output")
	cmd.PersistentFlags().Bool("silent", false, "Silent execution, no interactiveness")
	cmd.PersistentFlags().Bool("allow-output", false, "Allow stdout / stderr even when silent and not interactive")
	cmd.PersistentFlags().Bool("verbose", false, "Whether to verbose log")
	cmd.PersistentFlags().String("logger-style", "default", "Which verbose logger style to use")
	cmd.PersistentFlags().String("log-level", "INFO", "Log level to use while verbose")
	cmd.PersistentFlags().Bool("disable-cert-verification", false, "Disables certificate verification on HTTPS calls, unsafe! Avoid using in production environments!")
	cmd.PersistentFlags().String("trusted-cert", "", "Certificate to use for HTTPS calls")
	cmd.PersistentFlags().Bool("suppress-version-check", false, "Whether to suppress version check")
	cmd.PersistentFlags().Bool("disable-telemetry", false, "Disables telemetry data collection")
}

// CommonActionsExecution executes common actions based on the command line flags.
//
// CommonActionsExecution processes the standard flags set up by CommonActionsConfiguration
// and applies the corresponding configuration changes to the Idsec SDK runtime. This
// function should be called early in command execution to ensure proper setup.
//
// The function performs the following operations:
//  1. Sets default states for color, interactivity, logging, and certificates
//  2. Processes each flag and applies the corresponding configuration
//  3. Handles certificate verification settings (disable or trusted cert)
//  4. Configures profile name if provided
//  5. Sets default DEPLOY_ENV if not already set
//
// Parameters:
//   - cmd: The cobra command containing the parsed flags
//   - args: Command line arguments (not currently used but part of cobra pattern)
//
// The function ignores flag parsing errors and uses default values in such cases,
// following the principle of graceful degradation for CLI flag handling.
//
// Example:
//
//	action := NewIdsecBaseAction()
//	action.CommonActionsExecution(cmd, args, true)
func (a *IdsecBaseAction) CommonActionsExecution(cmd *cobra.Command, execArgs []string, printUpgrade bool) {
	config.EnableColor()
	config.EnableInteractive()
	config.DisableVerboseLogging()
	config.DisallowOutput()
	config.SetLoggerStyle(viper.GetString("logger-style"))
	config.EnableCertificateVerification()
	config.EnableTelemetryCollection()

	if raw, err := cmd.Flags().GetBool("raw"); err == nil && raw {
		config.DisableColor()
	}
	if silent, err := cmd.Flags().GetBool("silent"); err == nil && silent {
		config.DisableInteractive()
	}
	if verbose, err := cmd.Flags().GetBool("verbose"); err == nil && verbose {
		config.EnableVerboseLogging(viper.GetString("log-level"))
	}
	if allowOutput, err := cmd.Flags().GetBool("allow-output"); err == nil && allowOutput {
		config.AllowOutput()
	}
	if disableCertValidation, err := cmd.Flags().GetBool("disable-cert-verification"); err == nil && disableCertValidation {
		config.DisableCertificateVerification()
	} else if trustedCert, err := cmd.Flags().GetString("trusted-cert"); err == nil && trustedCert != "" {
		config.SetTrustedCertificate(viper.GetString("trusted-cert"))
	}
	if disableTelemetry, err := cmd.Flags().GetBool("disable-telemetry"); err == nil && disableTelemetry {
		config.DisableTelemetryCollection()
	}
	a.logger = common.GetLogger("IdsecBaseAction", common.Unknown)

	if profileName, err := cmd.Flags().GetString("profile-name"); err == nil && profileName != "" {
		viper.Set("profile-name", profiles.DeduceProfileName(profileName))
	}
	if os.Getenv("DEPLOY_ENV") == "" {
		_ = os.Setenv("DEPLOY_ENV", "prod")
	}
	if config.IsInteractive() && printUpgrade {
		if suppressVersionCheck, err := cmd.Flags().GetBool("suppress-version-check"); err == nil && suppressVersionCheck {
			return
		}
		if os.Getenv(suppressUpgradeCheckEnvVar) != "" {
			return
		}
		if !a.shouldCheckVersion() {
			return
		}
		isLatest, latestVersion, err := common.IsLatestVersion()
		if err == nil && !isLatest {
			a.updateVersionCheckTimestamp()
			if latestVersion != nil {
				args.PrintWarning(fmt.Sprintf("Newer version of Idsec SDK is available [%s], consider upgrading to the latest version\nYou may do so using `idsec upgrade` command", latestVersion.String()))
			} else {
				args.PrintWarning("Newer version of Idsec SDK is available, consider upgrading to the latest version\nYou may do so using `idsec upgrade` command")
			}
		}
	}
}

// shouldCheckVersion determines if a version check should be performed based on the last check timestamp.
//
// shouldCheckVersion reads a timestamp file from the idsec cache folder to determine if more than
// 24 hours have passed since the last version check. If the file doesn't exist or contains
// invalid data, it returns true to perform the check. If less than 24 hours have passed,
// it returns false to prevent spamming.
//
// Returns true if version check should be performed, false otherwise.
func (a *IdsecBaseAction) shouldCheckVersion() bool {
	profilesFolder := profiles.GetProfilesFolder()
	versionCheckFile := filepath.Join(profilesFolder, versionCheckFileName)
	if _, err := os.Stat(versionCheckFile); os.IsNotExist(err) {
		return true
	}
	data, err := os.ReadFile(versionCheckFile) // #nosec G304
	if err != nil {
		return true
	}
	lastCheckTime, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return true
	}
	now := time.Now().Unix()
	return now-lastCheckTime > versionCheckIntervalSeconds
}

// updateVersionCheckTimestamp updates the timestamp file to record when the version check was performed.
//
// updateVersionCheckTimestamp writes the current Unix timestamp to a file in the idsec cache folder
// to track when the last version check was performed. This prevents the version check warning
// from being displayed more than once per day.
func (a *IdsecBaseAction) updateVersionCheckTimestamp() {
	profilesFolder := profiles.GetProfilesFolder()
	if _, err := os.Stat(profilesFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(profilesFolder, 0750); err != nil {
			return
		}
	}
	versionCheckFile := filepath.Join(profilesFolder, versionCheckFileName)
	now := time.Now().Unix()
	_ = os.WriteFile(versionCheckFile, []byte(strconv.FormatInt(now, 10)), 0600)
}
