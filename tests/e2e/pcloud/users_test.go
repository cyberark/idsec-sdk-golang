//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pcloudusers "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestCreateAndDeleteUser tests basic Vault user creation and deletion.
func TestCreateAndDeleteUser(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete Vault User")

		usersSvc, err := ctx.API.PcloudUsers()
		require.NoError(t, err, "Failed to get PCloud Users service")

		username := framework.RandomResourceName("e2e-user")
		t.Logf("Creating user: %s", username)

		user, err := usersSvc.Create(&usersmodels.IdsecPCloudAddUser{
			Username:        username,
			InitialPassword: testUserPassword,
			UserType:        usersmodels.AppProviderUserType,
			Location:        "\\",
		})
		require.NoError(t, err, "Failed to create user")
		require.NotNil(t, user)
		assert.Greater(t, user.UserID, 0, "UserID must be populated after creation")
		assert.Equal(t, username, user.Username)
		assert.Equal(t, usersmodels.AppProviderUserType, user.UserType)

		t.Logf("User created: %s (ID: %d)", user.Username, user.UserID)

		ctx.TrackResourceByType("User", user.Username, func() error {
			return usersSvc.Delete(&usersmodels.IdsecPCloudDeleteUser{UserID: user.UserID})
		})
	}, pcloudusers.ServiceConfig)
}

// TestUserLifecycle tests the full Vault user lifecycle: Create -> Get -> Update -> Delete.
func TestUserLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: User Lifecycle (CRUD)")

		usersSvc, err := ctx.API.PcloudUsers()
		require.NoError(t, err, "Failed to get PCloud Users service")

		// 1. CREATE
		username := framework.RandomResourceName("e2e-user")
		t.Logf("Step 1: Creating user: %s", username)

		enabled := true
		changePass := false
		neverExpires := true

		user, err := usersSvc.Create(&usersmodels.IdsecPCloudAddUser{
			Username:              username,
			InitialPassword:       testUserPassword,
			UserType:              usersmodels.AppProviderUserType,
			Location:              "\\",
			EnableUser:            &enabled,
			ChangePassOnNextLogon: &changePass,
			PasswordNeverExpires:  &neverExpires,
		})
		require.NoError(t, err, "Failed to create user")
		require.NotNil(t, user)
		t.Logf("User created: %s (ID: %d)", user.Username, user.UserID)

		ctx.TrackResourceByType("User", user.Username, func() error {
			return usersSvc.Delete(&usersmodels.IdsecPCloudDeleteUser{UserID: user.UserID})
		})

		// 2. READ
		t.Logf("Step 2: Reading user: %d", user.UserID)
		retrieved, err := usersSvc.Get(&usersmodels.IdsecPCloudGetUser{UserID: user.UserID})
		require.NoError(t, err, "Failed to retrieve user")
		assert.Equal(t, user.UserID, retrieved.UserID)
		assert.Equal(t, username, retrieved.Username)
		assert.Equal(t, usersmodels.AppProviderUserType, retrieved.UserType)

		// 3. UPDATE
		t.Logf("Step 3: Updating user: %d", user.UserID)
		disabled := false
		updated, err := usersSvc.Update(&usersmodels.IdsecPCloudUpdateUser{
			UserID:     user.UserID,
			Username:   user.Username,
			EnableUser: &disabled,
		})
		require.NoError(t, err, "Failed to update user")
		require.NotNil(t, updated)

		// Verify update persisted
		retrieved, err = usersSvc.Get(&usersmodels.IdsecPCloudGetUser{UserID: user.UserID})
		require.NoError(t, err)
		require.NotNil(t, retrieved.EnableUser, "EnableUser should be present in response")
		assert.False(t, *retrieved.EnableUser, "User should be disabled after update")

		t.Log("User lifecycle completed successfully")
		// 4. DELETE happens via cleanup
	}, pcloudusers.ServiceConfig)
}

// TestGetNonExistentUser verifies that fetching an unknown user ID returns an error.
func TestGetNonExistentUser(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Get Non-Existent User")

		usersSvc, err := ctx.API.PcloudUsers()
		require.NoError(t, err, "Failed to get PCloud Users service")

		_, err = usersSvc.Get(&usersmodels.IdsecPCloudGetUser{UserID: 999999999})
		require.Error(t, err, "Expected error when fetching non-existent user")
		t.Logf("Got expected error: %v", err)
	}, pcloudusers.ServiceConfig)
}

// TestCreateUserInvalidType verifies that creating a user with an unlicensed type returns an error.
func TestCreateUserInvalidType(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create User with Invalid Type")

		usersSvc, err := ctx.API.PcloudUsers()
		require.NoError(t, err, "Failed to get PCloud Users service")

		_, err = usersSvc.Create(&usersmodels.IdsecPCloudAddUser{
			Username:        framework.RandomResourceName("e2e-user"),
			InitialPassword: testUserPassword,
			UserType:        "NonExistentType",
			Location:        "\\",
		})
		require.Error(t, err, "Expected error when creating user with invalid type")
		t.Logf("Got expected error: %v", err)
	}, pcloudusers.ServiceConfig)
}

// TestDeleteUserExplicit tests explicit deletion and verifies the user is no longer retrievable.
func TestDeleteUserExplicit(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Explicit User Deletion")

		usersSvc, err := ctx.API.PcloudUsers()
		require.NoError(t, err, "Failed to get PCloud Users service")

		username := framework.RandomResourceName("e2e-user")
		t.Logf("Creating user: %s", username)

		user, err := usersSvc.Create(&usersmodels.IdsecPCloudAddUser{
			Username:        username,
			InitialPassword: testUserPassword,
			UserType:        usersmodels.AppProviderUserType,
			Location:        "\\",
		})
		require.NoError(t, err, "Failed to create user")
		require.NotNil(t, user)
		t.Logf("User created: %s (ID: %d)", user.Username, user.UserID)

		// Verify exists
		_, err = usersSvc.Get(&usersmodels.IdsecPCloudGetUser{UserID: user.UserID})
		require.NoError(t, err, "User should exist before deletion")

		// Explicitly delete
		t.Logf("Deleting user: %d", user.UserID)
		err = usersSvc.Delete(&usersmodels.IdsecPCloudDeleteUser{UserID: user.UserID})
		require.NoError(t, err, "Delete should succeed")

		// Verify no longer retrievable
		_, err = usersSvc.Get(&usersmodels.IdsecPCloudGetUser{UserID: user.UserID})
		require.Error(t, err, "User should not be retrievable after deletion")
		t.Log("Explicit deletion verified successfully")
	}, pcloudusers.ServiceConfig)
}
