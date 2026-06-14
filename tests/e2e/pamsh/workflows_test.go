//go:build (e2e && pamsh) || e2e

package pamsh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pamshaccounts "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
	pamshsafes "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestCompleteVaultWorkflow testutils a complete end-to-end workflow against PAS via PVWA:
// 1. Create Safe
// 2. Add Safe Member
// 3. Create Account in Safe
// 4. Update Account
// 5. Cleanup (automatic via framework)
//
// This mirrors tests/e2e/pcloud/workflows_test.go TestCompleteVaultWorkflow in broad strokes;
// the safe member is pamshSafeMemberName (e2e-test-safe-member-user) rather than a built-in group.
// Accounts use pamshE2EActivePlatformID (UnixSSH), whereas pcloud workflow testutils often use WinLooselyDevice.
func TestCompleteVaultWorkflow(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Complete Vault Workflow (pamsh)")

		safesSvc := pamshSafesService(t, ctx)
		accountsSvc := pamshAccountsService(t, ctx)

		// ========================================
		// Step 1: Create Safe
		// ========================================
		t.Log("Step 1: Creating safe")
		safe := createPamshWorkflowSafe(t, ctx, "E2E workflow test safe", "e2e-safe-wf")
		t.Logf("✓ Safe created: %s (ID: %s)", safe.SafeName, safe.SafeID)

		// ========================================
		// Step 2: Add Safe Member (Optional)
		// ========================================
		memberName := pamshSafeMemberName(t)
		t.Logf("Step 2: Adding member '%s' to safe", memberName)

		var member *safesmodels.IdsecPamshSafeMember
		member, err := safesSvc.AddMember(&safesmodels.IdsecPamshAddSafeMember{
			SafeID:        safe.SafeID,
			MemberName:    memberName,
			MemberType:    safesmodels.User,
			PermissionSet: safesmodels.ReadOnly,
		})

		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist") {
				t.Logf("⚠ Skipping member addition: '%s' does not exist in environment", memberName)
			} else if strings.Contains(errMsg, "already a member") || strings.Contains(errMsg, "409") {
				t.Logf("⚠ Member '%s' already exists in safe (auto-added), verifying...", memberName)
				existingMember, verifyErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
					SafeID:     safe.SafeID,
					MemberName: memberName,
				})
				if verifyErr == nil {
					member = existingMember
					t.Logf("✓ Verified existing member: %s with %s permissions", member.MemberName, member.PermissionSet)
					trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, memberName)
				} else {
					t.Logf("⚠ Could not verify existing member: %v", verifyErr)
				}
			} else {
				require.NoError(t, err, "Failed to add safe member")
			}
		} else {
			require.NotNil(t, member)
			t.Logf("✓ Member added: %s with %s permissions", member.MemberName, member.PermissionSet)
			trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, memberName)
		}

		// ========================================
		// Step 3: Create Account in Safe
		// ========================================
		accountName := framework.RandomResourceName("e2e-acct-wf")
		testUsername := "workflow-user"
		testAddress := "workflow.example.com"
		testPassword := "WorkflowPassword123!"

		t.Logf("Step 3: Creating account '%s' in safe", accountName)

		account := createPamshTestAccount(t, ctx, accountsSvc, &accountsmodels.IdsecPamshAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   testUsername,
			Address:    testAddress,
			PlatformID: pamshE2EActivePlatformID,
			Secret:     testPassword,
		})

		t.Logf("✓ Account created: %s (ID: %s)", account.Name, account.AccountID)
		t.Logf("  Username: %s", account.Username)
		t.Logf("  Address: %s", account.Address)
		t.Logf("  Platform: %s", account.PlatformID)

		// ========================================
		// Step 4: Update Account
		// ========================================
		updatedAddress := "updated-workflow.example.com"
		t.Logf("Step 4: Updating account address to '%s'", updatedAddress)

		updatedAccount, err := accountsSvc.Update(&accountsmodels.IdsecPamshUpdateAccount{
			AccountID: account.AccountID,
			Address:   updatedAddress,
		})
		require.NoError(t, err, "Failed to update account")
		assert.Equal(t, updatedAddress, updatedAccount.Address)

		t.Logf("✓ Account updated successfully")

		retrievedAccount, err := accountsSvc.Get(&accountsmodels.IdsecPamshGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err, "Failed to retrieve updated account")
		assert.Equal(t, updatedAddress, retrievedAccount.Address)

		// ========================================
		// Step 5: Verify Complete State
		// ========================================
		t.Log("Step 5: Verifying complete workflow state")

		retrievedSafe, err := safesSvc.Get(&safesmodels.IdsecPamshGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err)
		assert.Equal(t, safe.SafeName, retrievedSafe.SafeName)

		assert.Equal(t, safe.SafeName, retrievedAccount.SafeName)
		assert.Equal(t, testUsername, retrievedAccount.Username)
		assert.Equal(t, updatedAddress, retrievedAccount.Address)

		t.Log("✓ Complete workflow verified successfully")
		t.Log("")
		t.Log("Workflow Summary:")
		t.Logf("  - Safe: %s", safe.SafeName)
		t.Logf("  - Account: %s@%s", retrievedAccount.Username, retrievedAccount.Address)
		t.Logf("  - Platform: %s", retrievedAccount.PlatformID)
		t.Log("")
		t.Log("Cleanup will execute in LIFO order:")
		t.Log("  1. Delete Account")
		if member != nil {
			t.Log("  2. Delete Safe Member")
			t.Log("  3. Delete Safe")
		} else {
			t.Log("  2. Delete Safe")
		}
	}, pamshsafes.ServiceConfig, pamshaccounts.ServiceConfig)
}

// TestMultiAccountWorkflow testutils creating multiple accounts in a single safe.
func TestMultiAccountWorkflow(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Multi-Account Workflow (pamsh)")

		accountsSvc := pamshAccountsService(t, ctx)

		t.Log("Creating safe for multi-account workflow")
		safe := createPamshTestSafe(t, ctx, "Multi-account workflow test", "e2e-safe-multiacct")
		t.Logf("Safe: %s (ID: %s)", safe.SafeName, safe.SafeID)

		accountConfigs := []struct {
			username string
			address  string
		}{
			{"ssh-user", "ssh.example.com"},
			{"admin-user", "admin.example.com"},
			{"app-user", "app.example.com"},
		}

		for i, config := range accountConfigs {
			accountName := framework.RandomResourceName("e2e-acct-multi")
			t.Logf("Creating account %d/%d: %s@%s", i+1, len(accountConfigs),
				config.username, config.address)

			createPamshTestAccount(t, ctx, accountsSvc, &accountsmodels.IdsecPamshAddAccount{
				SafeName:   safe.SafeName,
				Name:       accountName,
				Username:   config.username,
				Address:    config.address,
				PlatformID: pamshE2EActivePlatformID,
				Secret:     "TestPassword123!",
			})

			t.Logf("  ✓ Account created for %s@%s", config.username, config.address)
		}

		t.Log("Multi-account workflow completed successfully")
	}, pamshsafes.ServiceConfig, pamshaccounts.ServiceConfig)
}
