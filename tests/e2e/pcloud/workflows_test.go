//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accounts "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	safes "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestCompleteVaultWorkflow tests a complete end-to-end workflow:
// 1. Create Safe
// 2. Add Safe Member
// 3. Create Account in Safe
// 4. Retrieve Account Credentials
// 5. Update Account
// 6. Cleanup (automatic via framework)
//
// This mirrors the workflow in examples/pcloud/add_safe_account/add_safe_account.go
func TestCompleteVaultWorkflow(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Complete Vault Workflow")

		// Get services
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err, "Failed to get Safes service")

		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err, "Failed to get Accounts service")

		// ========================================
		// Step 1: Create Safe
		// ========================================
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Step 1: Creating safe '%s'", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:              safeName,
			Description:           "E2E workflow test safe",
			NumberOfDaysRetention: intPtr(0), // Set to 0 to allow immediate deletion
		})
		require.NoError(t, err, "Failed to create safe")
		require.NotNil(t, safe)

		t.Logf("✓ Safe created: %s (ID: %s)", safe.SafeName, safe.SafeID)

		// Register cleanup for safe (will be executed last due to LIFO)
		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			t.Logf("Cleaning up safe: %s", safe.SafeName)
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// ========================================
		// Step 2: Add Safe Member (Optional)
		// ========================================
		memberName := "Auditors" // Common built-in group
		t.Logf("Step 2: Adding member '%s' to safe", memberName)

		member, err := safesSvc.AddMember(&safesmodels.IdsecPCloudAddSafeMember{
			SafeID:        safe.SafeID,
			MemberName:    memberName,
			MemberType:    "Group",
			PermissionSet: safesmodels.ReadOnly,
		})

		if err != nil {
			// Handle various error cases gracefully
			errMsg := err.Error()
			if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist") {
				t.Logf("⚠ Skipping member addition: '%s' does not exist in environment", memberName)
			} else if strings.Contains(errMsg, "already a member") || strings.Contains(errMsg, "409") {
				// Member already exists (auto-added by safe creation), verify it instead
				t.Logf("⚠ Member '%s' already exists in safe (auto-added), verifying...", memberName)
				existingMember, verifyErr := safesSvc.GetMember(&safesmodels.IdsecPCloudGetSafeMember{
					SafeID:     safe.SafeID,
					MemberName: memberName,
				})
				if verifyErr == nil {
					member = existingMember
					t.Logf("✓ Verified existing member: %s with %s permissions", member.MemberName, member.PermissionSet)
				} else {
					t.Logf("⚠ Could not verify existing member: %v", verifyErr)
				}
			} else {
				require.NoError(t, err, "Failed to add safe member")
			}
		} else {
			require.NotNil(t, member)
			t.Logf("✓ Member added: %s with %s permissions", member.MemberName, member.PermissionSet)

			// Register cleanup for member (only if we added it)
			ctx.TrackResourceByType("SafeMember", memberName, func() error {
				t.Logf("Cleaning up safe member: %s", memberName)
				return safesSvc.DeleteMember(&safesmodels.IdsecPCloudDeleteSafeMember{
					SafeID:     safe.SafeID,
					MemberName: memberName,
				})
			})
		}

		// ========================================
		// Step 3: Create Account in Safe
		// ========================================
		accountName := framework.RandomResourceName("e2e-account")
		testUsername := "workflow-user"
		testAddress := "workflow.example.com"
		testPassword := "WorkflowPassword123!"

		t.Logf("Step 3: Creating account '%s' in safe", accountName)

		account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   testUsername,
			Address:    testAddress,
			PlatformID: "UnixSSH",
			Secret:     testPassword,
		})
		require.NoError(t, err, "Failed to create account")
		require.NotNil(t, account)

		t.Logf("✓ Account created: %s (ID: %s)", account.Name, account.AccountID)
		t.Logf("  Username: %s", account.Username)
		t.Logf("  Address: %s", account.Address)
		t.Logf("  Platform: %s", account.PlatformID)

		// Register cleanup for account (will be executed before safe due to LIFO)
		ctx.TrackResourceByType("Account", account.Name, func() error {
			t.Logf("Cleaning up account: %s", account.AccountID)
			return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
				AccountID: account.AccountID,
			})
		})

		// ========================================
		// Step 4: Retrieve Account Credentials
		// ========================================
		t.Logf("Step 4: Retrieving credentials for account '%s'", account.AccountID)

		credentials, err := accountsSvc.GetCredentials(&accountsmodels.IdsecPCloudGetAccountCredentials{
			AccountID: account.AccountID,
			Reason:    "E2E workflow test validation",
		})
		require.NoError(t, err, "Failed to retrieve credentials")
		require.NotNil(t, credentials)

		// Verify password matches what we set
		assert.Equal(t, testPassword, credentials.Password, "Retrieved password should match")
		t.Logf("✓ Credentials retrieved successfully")
		t.Logf("  Password length: %d characters", len(credentials.Password))

		// ========================================
		// Step 5: Update Account
		// ========================================
		updatedAddress := "updated-workflow.example.com"
		t.Logf("Step 5: Updating account address to '%s'", updatedAddress)

		updatedAccount, err := accountsSvc.Update(&accountsmodels.IdsecPCloudUpdateAccount{
			AccountID: account.AccountID,
			Address:   updatedAddress,
		})
		require.NoError(t, err, "Failed to update account")
		assert.Equal(t, updatedAddress, updatedAccount.Address)

		t.Logf("✓ Account updated successfully")

		// Verify the update persisted
		retrievedAccount, err := accountsSvc.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err, "Failed to retrieve updated account")
		assert.Equal(t, updatedAddress, retrievedAccount.Address)

		// ========================================
		// Step 6: Verify Complete State
		// ========================================
		t.Log("Step 6: Verifying complete workflow state")

		// Verify safe exists
		retrievedSafe, err := safesSvc.Get(&safesmodels.IdsecPCloudGetSafe{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err)
		assert.Equal(t, safe.SafeName, retrievedSafe.SafeName)

		// Verify account exists in safe
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
	}, safes.ServiceConfig, accounts.ServiceConfig)
}

// TestMultiAccountWorkflow tests creating multiple accounts in a single safe.
func TestMultiAccountWorkflow(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Multi-Account Workflow")

		// Get services
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err)

		// Create safe
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Multi-account workflow test",
		})
		require.NoError(t, err)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Create multiple accounts with different platforms
		accountConfigs := []struct {
			platform string
			username string
			address  string
		}{
			{"UnixSSH", "ssh-user", "ssh.example.com"},
			{"UnixSSH", "admin-user", "admin.example.com"},
			{"UnixSSH", "app-user", "app.example.com"},
		}

		createdAccounts := make([]*accountsmodels.IdsecPCloudAccount, 0, len(accountConfigs))

		for i, config := range accountConfigs {
			accountName := framework.RandomResourceName("e2e-account")
			t.Logf("Creating account %d/%d: %s@%s", i+1, len(accountConfigs),
				config.username, config.address)

			account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
				SafeName:   safe.SafeName,
				Name:       accountName,
				Username:   config.username,
				Address:    config.address,
				PlatformID: config.platform,
				Secret:     "TestPassword123!",
			})
			require.NoError(t, err, "Failed to create account %d", i+1)

			createdAccounts = append(createdAccounts, account)

			// Register cleanup
			accountID := account.AccountID
			ctx.TrackResourceByType("Account", account.Name, func() error {
				return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
					AccountID: accountID,
				})
			})

			t.Logf("  ✓ Account created: %s", account.AccountID)
		}

		// Verify all accounts exist in the safe
		t.Log("Verifying all accounts in safe...")
		accountsChan, err := accountsSvc.ListBy(&accountsmodels.IdsecPCloudAccountsFilter{
			SafeName: safe.SafeName,
		})
		require.NoError(t, err)

		foundCount := 0
		for page := range accountsChan {
			for _, account := range page.Items {
				if account.SafeName == safe.SafeName {
					foundCount++
				}
			}
		}

		assert.GreaterOrEqual(t, foundCount, len(accountConfigs),
			"Should find all created accounts")
		t.Logf("✓ Found %d accounts in safe (expected at least %d)",
			foundCount, len(accountConfigs))

		t.Log("Multi-account workflow completed successfully")
	}, safes.ServiceConfig, accounts.ServiceConfig)
}
