// Package common provides common models and utilities for AWS environment management
// and configuration handling within the IDSEC SDK. This package contains environment
// type definitions, environment detection utilities, and mapping configurations
// for different AWS environments including production and government cloud deployments.
package common

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// AwsEnv represents the AWS environment type used throughout the IDSEC SDK.
//
// This type is used to distinguish between different AWS deployment environments
// such as production and government cloud environments. It provides type safety
// when working with environment-specific configurations and mappings.
type AwsEnv string

// Constant variable and tenant configuration constants.
//
// These constants define the standard environment variables and default
// values used for environment detection and tenant configuration across
// different AWS environments.
const (
	// DeployEnv is the environment variable name used to determine the current deployment environment.
	DeployEnv = "DEPLOY_ENV"
	// IdentityTenantName is the default tenant name used for identity services.
	IdentityTenantName = "isp"
)

// AWS Environment constants for common environment values.
//
// These constants define the standard AWS environment identifiers used
// throughout the IDSEC SDK for environment-specific configuration and routing.
const (
	// Prod represents the production environment.
	Prod AwsEnv = "prod"
	// GovProd represents the GovCloud production environment.
	GovProd AwsEnv = "gov-prod"
)

type EnvObject struct {
	AwsEnv                         AwsEnv
	RootDomain                     string
	IdentityEnvURL                 string
	IdentityTenantName             string
	IdentityGeneratedSuffixPattern string
}

// AwsEnvList defines the mapping of AWS environments to their configuration details.
// This List provides all environment-specific configuration data including
// root domains, identity service URLs, tenant names, and suffix patterns for
// each AWS environment. This consolidates all environment configuration into
// a single, comprehensive mapping structure.
var AwsEnvList = []EnvObject{
	{
		AwsEnv:                         "prod",
		RootDomain:                     "cyberark.cloud",
		IdentityEnvURL:                 "idaptive.app",
		IdentityTenantName:             IdentityTenantName,
		IdentityGeneratedSuffixPattern: `cyberark\.cloud\.\d.*`,
	},
	{
		AwsEnv:                         "gov-prod",
		RootDomain:                     "cyberarkgov.cloud",
		IdentityEnvURL:                 "id.cyberarkgov.cloud",
		IdentityTenantName:             IdentityTenantName,
		IdentityGeneratedSuffixPattern: `cyberarkgov\.cloud\.\d.*`,
	},
}

// GetDeployEnv returns the current AWS environment based on the DEPLOY_ENV environment variable.
//
// This function reads the DEPLOY_ENV environment variable to determine the current
// deployment environment. If the environment variable is not set or is empty,
// it defaults to the production environment for backward compatibility.
//
// Returns the AwsEnv corresponding to the current deployment environment.
//
// Example:
//
//	// Set environment variable
//	os.Setenv("DEPLOY_ENV", "gov-prod")
//	env := GetDeployEnv()
//	if env == GovProd {
//	    // Handle GovCloud-specific logic
//	}
//
//	// Default behavior when not set
//	os.Unsetenv("DEPLOY_ENV")
//	env = GetDeployEnv() // Returns Prod
func GetDeployEnv() AwsEnv {
	deployEnv := os.Getenv(DeployEnv)
	if deployEnv == "" {
		return Prod
	}
	return AwsEnv(deployEnv)
}

// CheckIfIdentityGeneratedSuffix validates if a tenant suffix matches the environment-specific pattern.
//
// This function checks whether the provided tenant suffix matches the expected
// pattern for auto-generated identity suffixes in the specified AWS environment.
// It uses regex patterns defined in IdentityGeneratedSuffixPattern to perform
// the validation, helping to ensure proper tenant routing and identification.
//
// Parameters:
//   - tenantSuffix: The tenant suffix string to validate against the pattern
//   - env: The AWS environment to check the pattern against
//
// Returns true if the tenant suffix matches the environment's pattern, false otherwise.
// Returns false if the environment is not recognized or the pattern match fails.
//
// Example:
//
//	// Check production environment suffix
//	isValid := CheckIfIdentityGeneratedSuffix("cyberark.cloud.123", Prod)
//	if isValid {
//	    // Handle auto-generated tenant
//	}
//
//	// Check GovCloud environment suffix
//	isValid = CheckIfIdentityGeneratedSuffix("cyberarkgov.cloud.456", GovProd)
func CheckIfIdentityGeneratedSuffix(tenantSuffix string) bool {
	envObj, exists := GetAwsEnvFromList()
	if !exists {
		return false
	}
	matched, _ := regexp.MatchString(envObj.IdentityGeneratedSuffixPattern, tenantSuffix)
	return matched
}

// IsGovCloud determines if the current AWS region is a government cloud region.
//
// This function checks the AWS region environment variables to determine if the
// current deployment is running in an AWS GovCloud region. It first checks the
// AWS_REGION environment variable, and if that's not set, falls back to checking
// AWS_DEFAULT_REGION. GovCloud regions are identified by the "us-gov" prefix.
//
// Returns true if the current region is a GovCloud region, false otherwise.
// Returns false if no region environment variables are set.
//
// Example:
//
//	// Set GovCloud region
//	os.Setenv("AWS_REGION", "us-gov-west-1")
//	if IsGovCloud() {
//	    // Configure for GovCloud deployment
//	    env := GovProd
//	}
//
//	// Standard AWS region
//	os.Setenv("AWS_REGION", "us-east-1")
//	if !IsGovCloud() {
//	    // Configure for standard AWS deployment
//	    env := Prod
//	}
func IsGovCloud() bool {
	regionName := os.Getenv("AWS_REGION")
	if regionName == "" {
		regionName = os.Getenv("AWS_DEFAULT_REGION")
	}
	return strings.HasPrefix(regionName, "us-gov")
}

// GetAwsEnvFromList returns the environment configuration object for the specified AWS environment.
//
// This function searches through the AwsEnvList to find the configuration object
// that matches the provided AWS environment. It provides access to environment-specific
// configuration data including root domains, identity service URLs, tenant names,
// and suffix patterns for the specified environment.
//
// Parameters:
//   - env: The AWS environment to retrieve configuration for
//
// Returns the EnvObject for the specified environment and a boolean indicating if found.
// Returns an empty EnvObject and false if the environment is not recognized.
//
// Example:
//
//	// Get production environment configuration
//	envObj, found := GetAwsEnvFromList("prod")
//	if found {
//	    rootURL := envObj.RootDomain // "cyberark.cloud"
//	    identityURL := envObj.IdentityEnvUrl // "idaptive.app"
//	}
//
//	// Get GovCloud production environment configuration
//	envObj, found = GetAwsEnvFromList("gov-prod")
//	if found {
//	    rootURL := envObj.RootDomain // "cyberarkgov.cloud"
//	}
func GetAwsEnvFromList() (EnvObject, bool) {
	env := GetDeployEnv()
	for _, envObj := range AwsEnvList {
		if envObj.AwsEnv == env {
			return envObj, true
		}
	}
	return EnvObject{}, false
}

func ConcatEnv(e1 string, e2 string) string {
	if e1 == "" {
		return e2
	}
	if e2 == "" {
		return e1
	}
	if strings.HasSuffix(e1, "_") {
		return fmt.Sprintf("%s%s", e1, e2)
	}
	return fmt.Sprintf("%s_%s", e1, e2)
}
