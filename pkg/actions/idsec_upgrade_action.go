package actions

import (
	"fmt"
	"os"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// IdsecUpgradeAction is a struct that implements the IdsecAction interface for upgrading the CLI / SDK.
//
// IdsecUpgradeAction provides functionality for managing cache operations in the Idsec SDK CLI.
// It embeds IdsecBaseAction to inherit common CLI functionality and adds specific upgrade actions.
type IdsecUpgradeAction struct {
	// IdsecBaseAction provides common action functionality
	*IdsecBaseAction
}

// NewIdsecUpgradeAction creates a new instance of IdsecUpgradeAction.
//
// NewIdsecCacheAction initializes a new IdsecUpgradeAction with an embedded IdsecBaseAction,
// providing all the common CLI functionality along with cache-specific operations.
// The returned instance is ready to be used for defining upgrade commands.
//
// Returns a new IdsecUpgradeAction instance with initialized base action functionality.
//
// Example:
//
//	upgradeAction := NewIdsecUpgradeAction()
//	upgradeAction.DefineAction(rootCmd)
func NewIdsecUpgradeAction() *IdsecUpgradeAction {
	return &IdsecUpgradeAction{
		IdsecBaseAction: NewIdsecBaseAction(),
	}
}

// DefineAction defines the upgrade command and its configuration.
//
// DefineAction creates and configures the "upgrade" command with its flags and subcommands.
// It sets up the command structure, persistent flags for dry-run and version specification,
// and integrates with the common actions framework for consistent CLI behavior.
//
// Parameters:
//   - cmd: The parent cobra.Command to which the upgrade command will be added
//
// The method configures the following flags:
//   - --dry-run: Boolean flag to perform a dry run without actual upgrade
//   - --version: String flag to specify a particular version to upgrade to (default: latest)
//
// Example:
//
//	rootCmd := &cobra.Command{Use: "idsec"}
//	upgradeAction := NewIdsecUpgradeAction()
//	upgradeAction.DefineAction(rootCmd)
func (a *IdsecUpgradeAction) DefineAction(cmd *cobra.Command) {
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Manage upgrades",
		Run:   a.runUpgradeAction,
	}
	upgradeCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, false)
	}
	a.CommonActionsConfiguration(upgradeCmd)
	upgradeCmd.PersistentFlags().Bool("dry-run", false, "Whether to dry run")
	upgradeCmd.PersistentFlags().String("version", "", "Version to upgrade to (default: latest)")
	cmd.AddCommand(upgradeCmd)
}

// runUpgradeAction executes the upgrade functionality for the CLI/SDK.
//
// runUpgradeAction handles the core upgrade logic including version detection,
// GitHub release checking, and binary updating. It supports both dry-run mode
// for preview and actual upgrade execution. The function configures GitHub
// Enterprise support if GITHUB_URL environment variable is set.
//
// Parameters:
//   - cmd: The cobra.Command containing the parsed flags and configuration
//   - upgradeArgs: Command line arguments passed to the upgrade command
//
// The function performs the following operations:
//   - Configures GitHub updater with enterprise support if needed
//   - Parses current version and detects latest available version
//   - Handles specific version targeting via --version flag
//   - Executes dry-run preview if --dry-run flag is set
//   - Performs actual binary update if newer version is available
//   - Provides user feedback throughout the upgrade process
//
// Environment Variables:
//   - GITHUB_URL: Optional GitHub Enterprise URL for custom GitHub instances
//
// The function panics on critical errors such as version parsing failures,
// updater creation errors, or update execution failures.
//
// Example:
//
//	// Dry run to check available updates
//	idsec upgrade --dry-run
//
//	// Upgrade to latest version
//	idsec upgrade
//
//	// Upgrade to specific version
//	idsec upgrade --version v1.2.3
func (a *IdsecUpgradeAction) runUpgradeAction(cmd *cobra.Command, upgradeArgs []string) {
	updater, err := common.GetSelfUpgrader()
	if err != nil {
		a.logger.Error("Error creating updater %v", err)
		panic(err)
	}
	currentVersion, err := semver.Parse(config.IdsecVersion())
	if err != nil {
		a.logger.Error("Error parsing version %v", err)
		panic(err)
	}
	latest, found, err := updater.DetectLatest(config.IdsecPath())
	if err != nil {
		a.logger.Error("Error checking latest version %v", err)
		panic(err)
	}
	if !found {
		args.PrintNormal("No versions found")
		return
	}
	versionToUpgradeRelease := latest
	if versionStr, _ := cmd.Flags().GetString("version"); versionStr != "" {
		versionToUpgrade, err := semver.Parse(versionStr)
		if err != nil {
			a.logger.Error("Error parsing version %v", err)
			panic(err)
		}
		versionToUpgradeRelease, found, err = updater.DetectVersion(config.IdsecPath(), versionToUpgrade.String())
		if err != nil {
			a.logger.Error("Error checking version %v", err)
			panic(err)
		}
		if !found {
			args.PrintNormal(fmt.Sprintf("Version %s not found", versionToUpgrade.String()))
			return
		}
	}
	if cmd.Flags().Changed("dry-run") {
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		if dryRun {
			args.PrintNormalBright(fmt.Sprintf("Current version:\t%s", currentVersion.String()))
			args.PrintNormalBright(fmt.Sprintf("Version to upgrade:\t%s", versionToUpgradeRelease.Version.String()))
			if latest.Version.GT(currentVersion) {
				args.PrintNormalBright("An update is available.")
			} else {
				args.PrintSuccessBright("You are up-to-date.")
			}
			return
		}
	} else if versionToUpgradeRelease.Version.GT(currentVersion) {
		args.PrintNormalBright(fmt.Sprintf("Current version:\t%s", currentVersion.String()))
		args.PrintNormalBright(fmt.Sprintf("Version to upgrade:\t%s", versionToUpgradeRelease.Version.String()))
		if versionToUpgradeRelease.Version.EQ(latest.Version) {
			args.PrintNormalBright("Updating to the latest version...")
		} else {
			args.PrintNormalBright(fmt.Sprintf("Updating to %s version...", versionToUpgradeRelease.Version.String()))
		}
		cmdPath, err := os.Executable()
		if err != nil {
			a.logger.Error("Error getting executable path %v", err)
			panic(err)
		}
		err = updater.UpdateTo(versionToUpgradeRelease, cmdPath)
		if err != nil {
			a.logger.Error("Error updating to latest version %v", err)
			panic(err)
		}
		args.PrintSuccessBright(fmt.Sprintf("Successfully updated to version: %s", versionToUpgradeRelease.Version.String()))
	} else {
		args.PrintSuccessBright("You are up-to-date.")
	}
}
