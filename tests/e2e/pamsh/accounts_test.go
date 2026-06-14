//go:build (e2e && pamsh) || e2e

// Package pamsh holds E2E testutils against CyberArk PAS via PVWA. These testutils call a real PVWA
// base URL over TLS; run them only in an environment that trusts that endpoint (for example a
// container with your corporate CA / client cert installed). See testutils/e2e/README.md for env vars.
package pamsh

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pamshaccounts "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
	pamshsafes "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestPamshAccountLifecycleInDedicatedSafe creates a dedicated safe, creates an account in it,
// updates the account, reads it back via Get, and registers both for framework cleanup (LIFO).
// Requires: IDSEC_E2E_PVWA_* (see framework auth_providers).
func TestPamshAccountLifecycleInDedicatedSafe(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: pamsh account lifecycle in dedicated safe")

		safe := createPamshTestSafe(t, ctx, "E2E PAMSH dedicated safe for account lifecycle", "e2e-pamsh-acc-safe")
		t.Logf("Safe created: %s (ID: %s)", safe.SafeName, safe.SafeID)

		accountsSvc := pamshAccountsService(t, ctx)

		accountName := framework.RandomResourceName("e2e-account")
		t.Logf("Creating account in safe %q: %s", safe.SafeName, accountName)

		account := createPamshTestAccount(t, ctx, accountsSvc, &accountsmodels.IdsecPamshAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   "e2e-test-user",
			Address:    "e2e-test.example.com",
			PlatformID: pamshE2EActivePlatformID,
			Secret:     "TestPassword123!",
		})
		assert.Equal(t, accountName, account.Name)
		assert.Equal(t, "e2e-test-user", account.Username)
		t.Logf("Account created: %s (ID: %s)", account.Name, account.AccountID)

		t.Log("Updating account address...")
		updated, err := accountsSvc.Update(&accountsmodels.IdsecPamshUpdateAccount{
			AccountID: account.AccountID,
			Address:   "updated.example.com",
		})
		require.NoError(t, err, "Failed to update account")
		require.NotNil(t, updated)
		assert.Equal(t, "updated.example.com", updated.Address)

		retrieved, err := accountsSvc.Get(&accountsmodels.IdsecPamshGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err, "Failed to retrieve account after update")
		assert.Equal(t, "updated.example.com", retrieved.Address)
		t.Log("Account lifecycle steps completed; safe and account cleanup run via framework")
	}, pamshsafes.ServiceConfig, pamshaccounts.ServiceConfig)
}
