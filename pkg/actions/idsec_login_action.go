package actions

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/args"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// IdsecLoginAction is a struct that implements the IdsecAction interface for login action.
//
// IdsecLoginAction provides authentication functionality for the Idsec SDK CLI.
// It handles user authentication across multiple authentication methods and
// manages token storage and retrieval. The action supports interactive and
// non-interactive modes, shared secrets between authenticators, token refresh,
// and forced re-authentication.
//
// Key features:
//   - Multi-authenticator support (e.g., ISP, identity providers)
//   - Interactive credential prompting with shared secrets
//   - Token caching and refresh capabilities
//   - Force login and token display options
//   - Profile-based configuration management
type IdsecLoginAction struct {
	*IdsecBaseAction
	profilesLoader *profiles.ProfileLoader
}

// NewIdsecLoginAction creates a new instance of IdsecLoginAction.
//
// NewIdsecLoginAction initializes a new IdsecLoginAction with the provided profile
// loader for managing authentication profiles. The action inherits common
// functionality from IdsecBaseAction and configures profile-specific behavior.
//
// Parameters:
//   - profilesLoader: A ProfileLoader interface for loading and managing authentication profiles
//
// Returns a new IdsecLoginAction instance ready for CLI integration.
//
// Example:
//
//	loader := profiles.DefaultProfilesLoader()
//	action := NewIdsecLoginAction(loader)
//	action.DefineAction(rootCmd)
func NewIdsecLoginAction(profilesLoader *profiles.ProfileLoader) *IdsecLoginAction {
	return &IdsecLoginAction{
		IdsecBaseAction: NewIdsecBaseAction(),
		profilesLoader:  profilesLoader,
	}
}

// DefineAction defines the CLI `login` action, and adds the login function.
//
// DefineAction configures the login command with all necessary flags and
// behavior for authentication operations. The command supports various
// authentication options including profile selection, forced login,
// shared secrets management, token display, and refresh capabilities.
//
// Command flags added:
//   - profile-name: Specifies which profile to use for authentication
//   - force: Forces login even if valid tokens exist
//   - no-shared-secrets: Disables credential sharing between authenticators
//   - show-tokens: Displays authentication tokens in output
//   - refresh-auth: Attempts to refresh existing tokens from cache
//   - [authenticator]-username: Username for specific authenticators
//   - [authenticator]-secret: Secret/password for specific authenticators
//
// Parameters:
//   - cmd: The parent cobra command to attach the login command to
//
// The login command will be added as a subcommand with all configured flags
// and will execute the authentication workflow when invoked.
//
// Example:
//
//	action := NewIdsecLoginAction(loader)
//	action.DefineAction(rootCmd)
//	// Now 'idsec login' command is available
func (a *IdsecLoginAction) DefineAction(cmd *cobra.Command) {
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the system",
		Run:   a.runLoginAction,
	}
	loginCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		a.CommonActionsExecution(cmd, args, true)
	}
	a.CommonActionsConfiguration(loginCmd)

	loginCmd.Flags().String("profile-name", profiles.DefaultProfileName(), "Profile name to load")
	loginCmd.Flags().Bool("force", false, "Whether to force login even though token has not expired yet")
	loginCmd.Flags().Bool("no-shared-secrets", false, "Do not share secrets between different authenticators with the same username")
	loginCmd.Flags().Bool("show-tokens", false, "Print out tokens as well if not silent")
	loginCmd.Flags().Bool("refresh-auth", false, "If a cache exists, will also try to refresh it")

	for _, authenticator := range auth.SupportedAuthenticatorsList {
		loginCmd.Flags().String(fmt.Sprintf("%s-username", authenticator.AuthenticatorName()), "", fmt.Sprintf("Username to authenticate with to %s", authenticator.AuthenticatorHumanReadableName()))
		loginCmd.Flags().String(fmt.Sprintf("%s-secret", authenticator.AuthenticatorName()), "", fmt.Sprintf("Secret to authenticate with to %s", authenticator.AuthenticatorHumanReadableName()))
	}

	cmd.AddCommand(loginCmd)
}

// runLoginAction executes the authentication workflow for the login command.
//
// runLoginAction handles the complete authentication process including profile
// loading, credential gathering, authentication execution, and token management.
// It supports multiple authenticators simultaneously and manages shared secrets
// between compatible authentication methods.
//
// The function performs the following operations:
//  1. Loads the specified authentication profile
//  2. Iterates through configured authenticators
//  3. Checks existing authentication status and handles refresh/force options
//  4. Gathers credentials interactively or from command flags
//  5. Executes authentication for each configured authenticator
//  6. Manages shared secrets between compatible authenticators
//  7. Displays authentication results and tokens (if requested)
//
// Parameters:
//   - cmd: The cobra command containing parsed flags and configuration
//   - loginArgs: Command line arguments (currently unused)
//
// The function handles various authentication scenarios:
//   - Skip authentication if already authenticated (unless force=true)
//   - Refresh tokens if requested and possible
//   - Interactive credential prompting in interactive mode
//   - Shared secret reuse for compatible authentication methods
//   - Special handling for identity authentication without passwords
//   - Error handling and user feedback for failed authentication attempts
//
// Example:
//   Command: idsec login --profile-name prod --force --show-tokens
//   Result: Authenticates to all configured authenticators and displays tokens

func (a *IdsecLoginAction) runLoginAction(cmd *cobra.Command, loginArgs []string) {
	a.CommonActionsExecution(cmd, loginArgs, false)

	profileName, _ := cmd.Flags().GetString("profile-name")
	profile, err := a.loadProfileWithConfigureFlow(profileName, cmd)
	if err != nil {
		args.PrintFailure(fmt.Sprintf("Failed to load or configure profile: %v", err))
		return
	}

	sharedSecretsMap := make(map[authmodels.IdsecAuthMethod][][2]string)
	tokensMap := make(map[string]*authmodels.IdsecToken)

	for authenticatorName, authProfile := range profile.AuthProfiles {
		authenticator := auth.SupportedAuthenticators[authenticatorName]
		force, _ := cmd.Flags().GetBool("force")
		refreshAuth, _ := cmd.Flags().GetBool("refresh-auth")
		if !force {
			if authenticator.IsAuthenticated(profile) {
				if refreshAuth {
					_, err := authenticator.LoadAuthentication(profile, true)
					if err == nil {
						args.PrintSuccess(fmt.Sprintf("%s Authentication Refreshed", authenticator.AuthenticatorHumanReadableName()))
						continue
					}
					a.logger.Info("%s Failed to refresh token, performing normal login [%s]", authenticator.AuthenticatorHumanReadableName(), err.Error())
				} else {
					args.PrintSuccess(fmt.Sprintf("%s Already Authenticated", authenticator.AuthenticatorHumanReadableName()))
					continue
				}
			}
		}
		secretStr, _ := cmd.Flags().GetString(fmt.Sprintf("%s-secret", authenticatorName))
		secret := &authmodels.IdsecSecret{Secret: secretStr}
		userName, _ := cmd.Flags().GetString(fmt.Sprintf("%s-username", authenticatorName))
		if userName == "" {
			userName = authProfile.Username
		}
		if config.IsInteractive() && slices.Contains(authmodels.IdsecAuthMethodsRequireCredentials, authProfile.AuthMethod) {
			authProfile.Username, err = args.GetArg(
				cmd,
				fmt.Sprintf("%s-username", authenticatorName),
				fmt.Sprintf("%s Username", authenticator.AuthenticatorHumanReadableName()),
				userName,
				false,
				true,
				false,
			)
			if err != nil {
				args.PrintFailure(fmt.Sprintf("Failed to get %s username: %s", authenticatorName, err))
				return
			}
			if slices.Contains(authmodels.IdsecAuthMethodSharableCredentials, authProfile.AuthMethod) && len(sharedSecretsMap[authProfile.AuthMethod]) > 0 && !viper.GetBool("no-shared-secrets") {
				for _, s := range sharedSecretsMap[authProfile.AuthMethod] {
					if s[0] == authProfile.Username {
						secret = &authmodels.IdsecSecret{Secret: s[1]}
						break
					}
				}
			} else {
				if authenticatorName == "isp" &&
					authProfile.AuthMethod == authmodels.Identity &&
					!identity.IsPasswordRequired(authProfile.Username,
						authProfile.AuthMethodSettings.(*authmodels.IdentityIdsecAuthMethodSettings).IdentityURL,
						authProfile.AuthMethodSettings.(*authmodels.IdentityIdsecAuthMethodSettings).IdentityTenantSubdomain) {
					secret = &authmodels.IdsecSecret{Secret: ""}
				} else {
					secretStr, err = args.GetArg(
						cmd,
						fmt.Sprintf("%s-secret", authenticatorName),
						fmt.Sprintf("%s Secret", authenticator.AuthenticatorHumanReadableName()),
						secretStr,
						true,
						false,
						false,
					)
					if err != nil {
						args.PrintFailure(fmt.Sprintf("Failed to get %s secret: %s", authenticatorName, err))
						return
					}
					secret = &authmodels.IdsecSecret{Secret: secretStr}
				}
			}
		} else if !config.IsInteractive() && slices.Contains(authmodels.IdsecAuthMethodsRequireCredentials, authProfile.AuthMethod) && secret.Secret == "" {
			args.PrintFailure(fmt.Sprintf("%s-secret argument is required if authenticating to %s", authenticatorName, authenticator.AuthenticatorHumanReadableName()))
			return
		}

		// Reaching here means we need to authenticate for sure, as we either are forced to or not authenticated yet
		token, err := authenticator.Authenticate(profile, nil, secret, true, false)
		if err != nil {
			args.PrintFailure(fmt.Sprintf("Failed to authenticate with %s: %s", authenticator.AuthenticatorHumanReadableName(), err))
			return
		}

		noSharedSecrets, _ := cmd.Flags().GetBool("no-shared-secrets")
		if !noSharedSecrets && slices.Contains(authmodels.IdsecAuthMethodSharableCredentials, authProfile.AuthMethod) {
			sharedSecretsMap[authProfile.AuthMethod] = append(sharedSecretsMap[authProfile.AuthMethod], [2]string{authProfile.Username, secret.Secret})
		}
		tokensMap[authenticator.AuthenticatorHumanReadableName()] = token
	}
	showTokens, _ := cmd.Flags().GetBool("show-tokens")
	if !showTokens && len(tokensMap) > 0 {
		args.PrintSuccess("Login tokens are hidden")
	}

	for k, v := range tokensMap {
		if v.Metadata != nil {
			delete(v.Metadata, "cookies")
		}
		tokenMap := make(map[string]interface{})
		data, _ := json.Marshal(v)
		_ = json.Unmarshal(data, &tokenMap)
		if !showTokens {
			delete(tokenMap, "token")
			delete(tokenMap, "refresh_token")
		}
		jsonData, _ := json.MarshalIndent(tokenMap, "", "  ")
		args.PrintSuccess(fmt.Sprintf("%s Token\n%s", k, jsonData))
	}
}

// loadProfileWithConfigureFlow loads a profile by name, automatically triggering configure flow if no profile exists.
//
// loadProfileWithConfigureFlow attempts to load the specified profile and, if no valid profile
// is found, automatically starts the configuration flow to help users set up a profile.
// This provides a seamless user experience for login commands by eliminating the need to
// manually run configure commands when profiles are missing.
//
// Parameters:
//   - profileName: The name of the profile to load (will be processed through DeduceProfileName)
//   - cmd: The cobra command context for configuration
//
// Returns the loaded profile and any error that occurred during loading or configuration.
//
// Example usage:
//
//	profile, err := a.loadProfileWithConfigureFlow("production", cmd)
//	if err != nil {
//	    return fmt.Errorf("failed to load or configure profile: %v", err)
//	}
func (a *IdsecLoginAction) loadProfileWithConfigureFlow(profileName string, cmd *cobra.Command) (*models.IdsecProfile, error) {
	profile, err := (*a.profilesLoader).LoadProfile(profiles.DeduceProfileName(profileName))
	if err != nil || profile == nil {
		// Only start configure flow in interactive mode
		if config.IsInteractive() {
			args.PrintWarning("No profile found. Starting configuration flow...")

			// Create a configure action instance and run it
			configureAction := NewIdsecConfigureAction(a.profilesLoader)
			configureAction.runConfigureAction(cmd, []string{})

			// Reload profile after configuration
			profile, err = (*a.profilesLoader).LoadProfile(profiles.DeduceProfileName(profileName))
			if err != nil || profile == nil {
				return nil, fmt.Errorf("failed to load profile after configuration")
			}
		} else {
			// In non-interactive mode, just return an error
			return nil, fmt.Errorf("no profile found. Please run 'idsec configure' to set up a profile before using login")
		}
	}
	return profile, nil
}
