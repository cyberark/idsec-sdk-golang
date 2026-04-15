// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func TestGetBaseURL(t *testing.T) {
	origEnv := os.Getenv(common.DeployEnv)
	defer func() {
		_ = os.Unsetenv(common.DeployEnv)
		if origEnv != "" {
			_ = os.Setenv(common.DeployEnv, origEnv)
		}
	}()

	t.Run("prod env derives URL", func(t *testing.T) {
		_ = os.Setenv(common.DeployEnv, "prod")
		defer os.Unsetenv(common.DeployEnv)
		assert.Equal(t, "https://us-east-1-featureadopt.featureadopt.cyberark.cloud", getBaseURL())
	})


	t.Run("default prod when DEPLOY_ENV unset", func(t *testing.T) {
		_ = os.Unsetenv(common.DeployEnv)
		assert.Equal(t, "https://us-east-1-featureadopt.featureadopt.cyberark.cloud", getBaseURL())
	})

	t.Run("unknown env returns empty", func(t *testing.T) {
		_ = os.Setenv(common.DeployEnv, "staging")
		defer os.Unsetenv(common.DeployEnv)
		assert.Equal(t, "", getBaseURL())
	})

	t.Run("gov-prod returns empty (FAS only for prod and integration)", func(t *testing.T) {
		_ = os.Setenv(common.DeployEnv, "gov-prod")
		defer os.Unsetenv(common.DeployEnv)
		assert.Equal(t, "", getBaseURL())
	})
}
