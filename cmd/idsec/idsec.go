// Package main provides the entry point for the Idsec CLI application.
//
// The Idsec CLI is a command-line interface that provides access to various
// Idsec services and functionality including profile management, authentication,
// configuration, caching, and service execution.
//
// The application uses the Cobra library for command-line interface management
// and supports multiple subcommands for different operations. Build information
// including version, build number, build date, and git commit are embedded
// at compile time through build variables.
//
// Example usage:
//
//	idsec --version
//	idsec profiles list
//	idsec login
//	idsec configure
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"

	"github.com/cyberark/idsec-sdk-golang/pkg/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// main is the entry point for the Idsec CLI application.
//
// This function initializes the Cobra root command with version information,
// sets up the application version in the common package, creates a profiles
// loader, and registers all available actions (profiles, cache, configure,
// login, and service execution) with the root command.
//
// The function handles command execution and exits with code 1 if an error
// occurs during command execution. The version template is customized to
// display build information in a specific format.
//
// Build variables (GitCommit, BuildDate, Version, BuildNumber) are expected
// to be set at compile time using ldflags but will default to "N/A" if not
// provided.
//
// Available commands after initialization:
//   - profiles: Manage user profiles
//   - cache: Manage application cache
//   - configure: Configure the CLI
//   - login: Authenticate with services
//   - exec: Execute service actions
//
// The function will call os.Exit(1) if command execution fails.
func main() {
	var rootCmd = &cobra.Command{
		Use: "idsec",
		Version: fmt.Sprintf(
			"Version: %s\nBuild Number: %s\nBuild Date: %s\nGit Commit: %s\nGit Branch: %s",
			config.IdsecVersion(),
			config.IdsecBuildNumber(),
			config.IdsecBuildDate(),
			config.IdsecGitCommit(),
			config.IdsecGitBranch(),
		),
		Short: "Idsec CLI",
	}
	rootCmd.SetVersionTemplate("{{.Version}}\n")
	config.SetIdsecToolInUse(config.IdsecToolCLI)
	profilesLoader := profiles.DefaultProfilesLoader()
	idsecActions := []actions.IdsecAction{
		actions.NewIdsecProfilesAction(profilesLoader),
		actions.NewIdsecCacheAction(),
		actions.NewIdsecConfigureAction(profilesLoader),
		actions.NewIdsecLoginAction(profilesLoader),
		actions.NewIdsecServiceExecAction(profilesLoader),
		actions.NewIdsecUpgradeAction(),
	}

	for _, action := range idsecActions {
		action.DefineAction(rootCmd)
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
