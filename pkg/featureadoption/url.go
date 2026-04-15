// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// fasBaseURLEnvVar overrides the FAS base URL when set. Used for testing and local debugging.
const fasBaseURLEnvVar = "FAS_BASE_URL"

// getBaseURL returns the FAS base URL derived from DEPLOY_ENV (the regular Idsec environment).
// FAS is only available for prod and integration; returns empty for all other environments.
// When FAS_BASE_URL is set, it overrides the derived URL (for tests and debugging).
// Full endpoint format: https://us-east-1-featureadopt.featureadopt.{root domain}/api/feature-adoption
func getBaseURL() string {
	if override := os.Getenv(fasBaseURLEnvVar); override != "" {
		return override
	}
	envObj, ok := common.GetAwsEnvFromList()
	if !ok || envObj.RootDomain == "" {
		return ""
	}
	switch envObj.AwsEnv {
	case common.Prod, common.AwsEnv("integration"):
		return fmt.Sprintf("https://us-east-1-featureadopt.featureadopt.%s", envObj.RootDomain)
	default:
		return ""
	}
}
