//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accounts "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestListAccounts verifies that we can successfully list PCloud accounts.
func TestListAccounts(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List PCloud Accounts")

		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err, "Failed to get PCloud Accounts service")

		// List accounts
		t.Log("Listing PCloud accounts...")
		accountsChan, err := accountsSvc.List()
		require.NoError(t, err, "Failed to list accounts")

		// Count accounts
		accountCount := 0
		for page := range accountsChan {
			accountCount += len(page.Items)
			if len(page.Items) > 0 && accountCount <= 5 {
				// Log first few accounts for visibility
				for _, account := range page.Items {
					t.Logf("  Account: %s@%s (Safe: %s)",
						account.Username, account.Address, account.SafeName)
				}
			}
		}

		t.Logf("Found %d account(s)", accountCount)
		assert.NotNil(t, accountsChan, "Accounts channel should not be nil")
	}, accounts.ServiceConfig)
}

// TestCreateAndDeleteAccount tests basic account creation and deletion.
func TestCreateAndDeleteAccount(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete Account")

		// Get services
		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err)

		// Create a safe first
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Test safe for account operations",
		})
		require.NoError(t, err)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Create an account
		accountName := framework.RandomResourceName("e2e-account")
		t.Logf("Creating account: %s", accountName)

		account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   "e2e-test-user",
			Address:    "e2e-test.example.com",
			PlatformID: "UnixSSH",
			Secret:     "TestPassword123!",
		})
		require.NoError(t, err, "Failed to create account")
		require.NotNil(t, account)
		assert.Equal(t, accountName, account.Name)
		assert.Equal(t, "e2e-test-user", account.Username)

		t.Logf("Account created successfully: %s (ID: %s)", account.Name, account.AccountID)

		// Register cleanup (account must be deleted before safe)
		ctx.TrackResourceByType("Account", account.Name, func() error {
			t.Logf("Cleaning up account: %s", account.AccountID)
			return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
				AccountID: account.AccountID,
			})
		})

		// Verify account exists
		t.Log("Verifying account exists...")
		retrievedAccount, err := accountsSvc.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err, "Failed to retrieve account")
		assert.Equal(t, account.AccountID, retrievedAccount.AccountID)
		assert.Equal(t, account.Username, retrievedAccount.Username)

		t.Log("Account verified successfully")
	}, accounts.ServiceConfig)
}

// TestAccountLifecycle tests the complete account lifecycle: Create -> Get -> Update -> Delete.
// This is a comprehensive CRUD test that exercises all account operations.
func TestAccountLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Account Lifecycle (CRUD)")

		// Create a safe using helper
		safe := createTestSafe(t, ctx, "Test safe for account lifecycle")

		// Get accounts service
		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err)

		// 1. CREATE
		accountName := framework.RandomResourceName("e2e-account")
		t.Logf("Step 1: Creating account: %s", accountName)

		account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   "testuser",
			Address:    testAddress,
			PlatformID: testPlatformUnixSSH,
			Secret:     "InitialPassword123!",
		})
		require.NoError(t, err)
		t.Logf("Account created: %s", account.AccountID)

		ctx.TrackResourceByType("Account", account.Name, func() error {
			return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
				AccountID: account.AccountID,
			})
		})

		// 2. READ
		t.Logf("Step 2: Reading account: %s", account.AccountID)
		retrievedAccount, err := accountsSvc.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err)
		assert.Equal(t, account.AccountID, retrievedAccount.AccountID)
		assert.Equal(t, "testuser", retrievedAccount.Username)

		// 3. UPDATE
		t.Logf("Step 3: Updating account: %s", account.AccountID)
		updatedAccount, err := accountsSvc.Update(&accountsmodels.IdsecPCloudUpdateAccount{
			AccountID: account.AccountID,
			Address:   "updated.example.com",
		})
		require.NoError(t, err)
		assert.Equal(t, "updated.example.com", updatedAccount.Address)

		// Verify update
		retrievedAccount, err = accountsSvc.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err)
		assert.Equal(t, "updated.example.com", retrievedAccount.Address)

		t.Log("Account lifecycle completed successfully")
		// 4. DELETE happens automatically via cleanup
	}, accounts.ServiceConfig)
}

// TestRetrieveAccountCredentials tests retrieving account credentials.
func TestRetrieveAccountCredentials(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Retrieve Account Credentials")

		// Create a safe using helper
		safe := createTestSafe(t, ctx, "Test safe for credentials")

		// Create an account with a known password using helper
		account := createTestAccountWithPassword(t, ctx, safe.SafeName, testPassword)

		// Get accounts service for credential retrieval
		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err)

		// Retrieve credentials
		t.Logf("Retrieving credentials for account: %s", account.AccountID)
		credentials, err := accountsSvc.GetCredentials(&accountsmodels.IdsecPCloudGetAccountCredentials{
			AccountID: account.AccountID,
			Reason:    "E2E test validation",
		})
		require.NoError(t, err, "Failed to retrieve account credentials")
		require.NotNil(t, credentials)

		// Verify password
		assert.Equal(t, testPassword, credentials.Password, "Retrieved password should match")
		t.Logf("Successfully retrieved credentials for account")
	}, accounts.ServiceConfig)
}

// TestListAccountsBySafe tests filtering accounts by safe name.
func TestListAccountsBySafe(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List Accounts By Safe")

		// Create a safe using helper
		safe := createTestSafe(t, ctx, "Test safe for filtered listing")

		// Get accounts service
		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err)

		// Create multiple accounts in the safe using helper
		numAccounts := 3
		for i := 0; i < numAccounts; i++ {
			createTestAccount(t, ctx, safe.SafeName)
		}

		t.Logf("Created %d accounts in safe: %s", numAccounts, safe.SafeName)

		// List accounts filtered by safe
		t.Log("Listing accounts in the safe...")
		accountsChan, err := accountsSvc.ListBy(&accountsmodels.IdsecPCloudAccountsFilter{
			SafeName: safe.SafeName,
		})
		require.NoError(t, err)

		// Count accounts in this safe
		foundCount := 0
		for page := range accountsChan {
			for _, account := range page.Items {
				if account.SafeName == safe.SafeName {
					foundCount++
					t.Logf("  Found account: %s", account.Name)
				}
			}
		}

		assert.GreaterOrEqual(t, foundCount, numAccounts,
			"Should find at least the accounts we created")
		t.Logf("Found %d accounts in safe (expected at least %d)", foundCount, numAccounts)
	}, accounts.ServiceConfig)
}

// TestDeleteAccountExplicit tests the delete API explicitly.
// Unlike other tests that rely on automatic cleanup, this test explicitly calls
// the Delete API and verifies the operation succeeds (returns 200).
func TestDeleteAccountExplicit(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Explicit Account Deletion")

		// Create a safe using helper
		safe := createTestSafe(t, ctx, "Test safe for explicit deletion")

		// Get accounts service
		accountsSvc, err := ctx.API.PcloudAccounts()
		require.NoError(t, err, "Failed to get PCloud Accounts service")

		// Create an account (manually, not using helper, to avoid auto-cleanup registration)
		accountName := framework.RandomResourceName("e2e-account")
		t.Logf("Creating account: %s", accountName)

		account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
			SafeName:   safe.SafeName,
			Name:       accountName,
			Username:   testUsername,
			Address:    testAddress,
			PlatformID: testPlatformUnixSSH,
			Secret:     testPassword,
		})
		require.NoError(t, err, "Failed to create account")
		require.NotNil(t, account)
		require.NotEmpty(t, account.AccountID, "AccountID must be populated after creation")
		t.Logf("Account created: %s (ID: %s)", account.Name, account.AccountID)

		// Verify account exists before deletion (with eventual consistency handling)
		t.Log("Verifying account exists before deletion...")
		var retrievedAccount *accountsmodels.IdsecPCloudAccount
		require.Eventually(t, func() bool {
			var getErr error
			retrievedAccount, getErr = accountsSvc.Get(&accountsmodels.IdsecPCloudGetAccount{
				AccountID: account.AccountID,
			})
			return getErr == nil
		}, 30*time.Second, 1*time.Second, "Account should be visible after creation")

		require.Equal(t, account.AccountID, retrievedAccount.AccountID, "Account ID mismatch")

		// Explicitly delete the account (NOT via cleanup)
		t.Logf("Explicitly deleting account: %s", account.AccountID)
		err = accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
			AccountID: account.AccountID,
		})
		require.NoError(t, err, "Delete should succeed with 200 status")

		t.Log("Explicit deletion test completed successfully")
		// Note: Safe cleanup happens automatically via createTestSafe helper
	}, accounts.ServiceConfig)
}
