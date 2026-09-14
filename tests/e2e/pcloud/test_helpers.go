//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	usergroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/models"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// Test constants for consistent values across tests
const (
	testPlatformUnixSSH = "UnixSSH"
	testAddress         = "test.example.com"
	testUsername        = "e2e-test-user"
	testPassword        = "TestPassword123!"
	testUserPassword    = "SomeRandomPass123!"
)

// requireEnvInt reads an environment variable as an integer.
// Skips the test if the variable is not set or cannot be parsed.
func requireEnvInt(t *testing.T, envVar string) int {
	t.Helper()
	val := os.Getenv(envVar)
	if val == "" {
		t.Skipf("Skipping: %s is not set", envVar)
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		t.Skipf("Skipping: %s=%q is not a valid integer", envVar, val)
	}
	return n
}

// requireEnv reads an environment variable as a string.
// Skips the test if the variable is not set.
func requireEnv(t *testing.T, envVar string) string {
	t.Helper()
	val := os.Getenv(envVar)
	if val == "" {
		t.Skipf("Skipping: %s is not set", envVar)
	}
	return val
}

// createTestSafe creates a safe with the given description and registers automatic cleanup.
// This helper reduces boilerplate in tests that need a safe as a prerequisite.
func createTestSafe(t *testing.T, ctx *framework.TestContext, description string) *safesmodels.IdsecPCloudSafe {
	t.Helper()

	safesSvc, err := ctx.API.PcloudSafes()
	require.NoError(t, err, "Failed to get PCloud Safes service")

	safeName := framework.RandomResourceName("e2e-safe")
	t.Logf("Creating test safe: %s", safeName)

	safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
		SafeName:    safeName,
		Description: description,
	})
	require.NoError(t, err, "Failed to create test safe")

	// Register cleanup (will be executed in LIFO order)
	ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
		return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
			SafeID: safe.SafeID,
		})
	})

	return safe
}

// createTestAccount creates an account in the given safe and registers automatic cleanup.
// This helper reduces boilerplate in tests that need an account as a prerequisite.
func createTestAccount(t *testing.T, ctx *framework.TestContext, safeName string) *accountsmodels.IdsecPCloudAccount {
	t.Helper()

	accountsSvc, err := ctx.API.PcloudAccounts()
	require.NoError(t, err, "Failed to get PCloud Accounts service")

	accountName := framework.RandomResourceName("e2e-account")
	t.Logf("Creating test account: %s", accountName)

	account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
		SafeName:   safeName,
		Name:       accountName,
		Username:   testUsername,
		Address:    testAddress,
		PlatformID: testPlatformUnixSSH,
		Secret:     testPassword,
	})
	require.NoError(t, err, "Failed to create test account")

	// Register cleanup (will be executed in LIFO order, before safe deletion)
	ctx.TrackResourceByType("Account", account.Name, func() error {
		return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
			AccountID: account.AccountID,
		})
	})

	return account
}

// createTestAccountWithPassword creates an account with a specific password and registers cleanup.
// Useful for credential retrieval tests where the password needs to be verified.
func createTestAccountWithPassword(t *testing.T, ctx *framework.TestContext, safeName, password string) *accountsmodels.IdsecPCloudAccount {
	t.Helper()

	accountsSvc, err := ctx.API.PcloudAccounts()
	require.NoError(t, err, "Failed to get PCloud Accounts service")

	accountName := framework.RandomResourceName("e2e-account")
	t.Logf("Creating test account with custom password: %s", accountName)

	account, err := accountsSvc.Create(&accountsmodels.IdsecPCloudAddAccount{
		SafeName:   safeName,
		Name:       accountName,
		Username:   testUsername,
		Address:    testAddress,
		PlatformID: testPlatformUnixSSH,
		Secret:     password,
	})
	require.NoError(t, err, "Failed to create test account")

	// Register cleanup
	ctx.TrackResourceByType("Account", account.Name, func() error {
		return accountsSvc.Delete(&accountsmodels.IdsecPCloudDeleteAccount{
			AccountID: account.AccountID,
		})
	})

	return account
}

// createTestUser creates an AppProvider Vault user and registers automatic cleanup.
// This helper reduces boilerplate in tests that need a Vault user as a prerequisite.
func createTestUser(t *testing.T, ctx *framework.TestContext) *usersmodels.IdsecPCloudUser {
	t.Helper()

	usersSvc, err := ctx.API.PcloudUsers()
	require.NoError(t, err, "Failed to get PCloud Users service")

	username := framework.RandomResourceName("e2e-user")
	t.Logf("Creating test user: %s", username)

	user, err := usersSvc.Create(&usersmodels.IdsecPCloudAddUser{
		Username:        username,
		InitialPassword: testUserPassword,
		UserType:        usersmodels.AppProviderUserType,
		Location:        "\\",
	})
	require.NoError(t, err, "Failed to create test user")

	ctx.TrackResourceByType("User", user.Username, func() error {
		return usersSvc.Delete(&usersmodels.IdsecPCloudDeleteUser{UserID: user.UserID})
	})

	return user
}

// createTestUserGroup creates a Vault user group and registers automatic cleanup.
// This helper reduces boilerplate in tests that need a group as a prerequisite.
func createTestUserGroup(t *testing.T, ctx *framework.TestContext) *usergroupsmodels.IdsecPCloudUserGroup {
	t.Helper()

	ugSvc, err := ctx.API.PcloudUsergroups()
	require.NoError(t, err, "Failed to get PCloud UserGroups service")

	groupName := framework.RandomResourceName("e2e-group")
	t.Logf("Creating test user group: %s", groupName)

	group, err := ugSvc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{
		GroupName:   groupName,
		Description: "e2e test group",
		Location:    "\\",
	})
	require.NoError(t, err, "Failed to create test user group")

	ctx.TrackResourceByType("UserGroup", groupName, func() error {
		return ugSvc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: group.GroupID})
	})

	return group
}

// intPtr is a helper to create a pointer to an int value.
// Useful for struct fields that require *int.
func intPtr(i int) *int {
	return &i
}
