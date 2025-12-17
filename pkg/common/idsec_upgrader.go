// Package common provides utility functions for the IDSEC SDK, including self-update functionality
// for checking and managing application versions using GitHub releases.
package common

import (
	"fmt"
	"os"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
)

// GetSelfUpgrader creates and configures a GitHub self-updater instance.
//
// This function initializes a self-updater that can work with both public GitHub
// and GitHub Enterprise instances. The configuration is determined by the GITHUB_URL
// environment variable - if set, it configures the updater for GitHub Enterprise
// using the provided base URL.
//
// The function sets up the appropriate API endpoints:
// - For GitHub Enterprise: uses custom upload and base URLs
// - For public GitHub: uses default configuration
//
// Returns a configured selfupdate.Updater instance that can be used to check for
// and download application updates.
//
// Example:
//
//	updater, err := GetSelfUpgrader()
//	if err != nil {
//	    // handle error
//	}
//	// Use updater to check for updates
func GetSelfUpgrader() (*selfupdate.Updater, error) {
	githubURL := os.Getenv("GITHUB_URL")
	config := selfupdate.Config{}
	if githubURL != "" {
		config.EnterpriseUploadURL = fmt.Sprintf("https://%s/api/uploads/", githubURL)
		config.EnterpriseBaseURL = fmt.Sprintf("https://%s/api/v3/", githubURL)
	}
	return selfupdate.NewUpdater(config)
}

// IsLatestVersion checks if the current application version is the latest available.
//
// This function compares the current application version (from IdsecVersion()) with the
// latest version available in the GitHub repository. It handles both public GitHub
// and GitHub Enterprise instances based on the GITHUB_URL environment variable.
//
// The function performs the following steps:
// 1. Creates a self-updater instance
// 2. Detects the latest available version from GitHub releases
// 3. Parses the current application version
// 4. Compares versions using semantic versioning
//
// Returns:
//   - bool: true if current version is latest or newer, false if update available
//   - *semver.Version: the latest version found (nil if no releases found)
//   - error: any error encountered during version checking
//
// The function returns (true, nil, nil) if no releases are found in the repository,
// indicating that the current version should be considered up-to-date.
//
// Example:
//
//	isLatest, latestVer, err := IsLatestVersion()
//	if err != nil {
//	    // handle error
//	}
//	if !isLatest {
//	    fmt.Printf("Update available: %s\n", latestVer.String())
//	}
func IsLatestVersion() (bool, *semver.Version, error) {
	updater, err := GetSelfUpgrader()
	if err != nil {
		return false, nil, err
	}
	latest, found, err := updater.DetectLatest(config.IdsecPath())
	if err != nil {
		return false, nil, err
	}
	if !found {
		return true, nil, nil
	}
	currentVersion, err := semver.Parse(config.IdsecVersion())
	if err != nil {
		return false, nil, err
	}
	return !latest.Version.GT(currentVersion), &latest.Version, nil
}
