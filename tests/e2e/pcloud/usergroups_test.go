//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pcloudUserGroups "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups"
	usergroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/usergroups/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestAddAndDeleteUserGroupMember tests basic addition of a Vault user to a group and cleanup.
// Requires IDSEC_E2E_GROUP_ID and IDSEC_E2E_MEMBER_NAME environment variables.
func TestAddAndDeleteUserGroupMember(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Add and Delete User Group Member")

		groupID := requireEnvInt(t, "IDSEC_E2E_GROUP_ID")
		memberName := requireEnv(t, "IDSEC_E2E_MEMBER_NAME")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		t.Logf("Adding user [%s] to group [%d]", memberName, groupID)

		member, err := ugSvc.AddMember(&usergroupsmodels.IdsecPCloudAddUserGroupMember{
			GroupID:    groupID,
			MemberName: memberName,
			MemberType: "Vault",
		})
		require.NoError(t, err, "Failed to add user to group")
		require.NotNil(t, member)
		assert.Equal(t, groupID, member.GroupID)
		assert.Equal(t, memberName, member.MemberName)

		t.Logf("Member added: userName=%s groupID=%d", member.MemberName, member.GroupID)

		ctx.TrackResourceByType("UserGroupMember", fmt.Sprintf("%d/%s", groupID, memberName), func() error {
			return ugSvc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
				GroupID:    groupID,
				MemberName: memberName,
			})
		})
	}, pcloudUserGroups.ServiceConfig)
}

// TestUserGroupMemberLifecycle tests the full lifecycle: add member → verify response fields → explicitly delete.
// Requires IDSEC_E2E_GROUP_ID and IDSEC_E2E_MEMBER_NAME environment variables.
func TestUserGroupMemberLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: User Group Member Lifecycle")

		groupID := requireEnvInt(t, "IDSEC_E2E_GROUP_ID")
		memberName := requireEnv(t, "IDSEC_E2E_MEMBER_NAME")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		// 1. ADD
		t.Logf("Step 1: Adding user [%s] to group [%d]", memberName, groupID)
		member, err := ugSvc.AddMember(&usergroupsmodels.IdsecPCloudAddUserGroupMember{
			GroupID:    groupID,
			MemberName: memberName,
			MemberType: "Vault",
		})
		require.NoError(t, err, "Failed to add member to group")
		require.NotNil(t, member)

		// The group is a pre-existing tenant group, so a membership left behind by a failure
		// between here and step 2 would collide with the next run. As in the group lifecycle
		// test, the cleanup is a no-op once step 2 has removed the member itself.
		memberRemoved := false
		ctx.TrackResourceByType("UserGroupMember", fmt.Sprintf("%d/%s", groupID, memberName), func() error {
			if memberRemoved {
				return nil
			}
			return ugSvc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
				GroupID:    groupID,
				MemberName: memberName,
			})
		})

		assert.Equal(t, groupID, member.GroupID)
		assert.Equal(t, memberName, member.MemberName)
		assert.Equal(t, "Vault", member.MemberType)

		// 2. DELETE (explicit, not via cleanup)
		t.Logf("Step 2: Removing user [%s] from group [%d]", memberName, groupID)
		err = ugSvc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
			GroupID:    groupID,
			MemberName: memberName,
		})
		require.NoError(t, err, "DeleteMember should succeed")
		memberRemoved = true
		t.Log("Member removed successfully")
	}, pcloudUserGroups.ServiceConfig)
}

// TestDeleteNonExistentGroupMember verifies that removing a non-existent member returns an error.
// Requires IDSEC_E2E_GROUP_ID environment variable.
func TestDeleteNonExistentGroupMember(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Delete Non-Existent Group Member")

		groupID := requireEnvInt(t, "IDSEC_E2E_GROUP_ID")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		err = ugSvc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
			GroupID:    groupID,
			MemberName: "idsec-e2e-nonexistent-member",
		})
		require.Error(t, err, "Expected error when deleting non-existent group member")
		t.Logf("Got expected error: %v", err)
	}, pcloudUserGroups.ServiceConfig)
}

// TestCreateAndDeleteUserGroup tests creating a user group and verifying cleanup.
func TestCreateAndDeleteUserGroup(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create and Delete User Group")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		groupName := framework.RandomResourceName("e2e-group")
		t.Logf("Creating user group: %s", groupName)

		group, err := ugSvc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{
			GroupName:   groupName,
			Description: "e2e test group",
			Location:    "\\",
		})
		require.NoError(t, err, "Failed to create user group")
		require.NotNil(t, group)
		assert.NotZero(t, group.GroupID, "GroupID should be non-zero")
		assert.Equal(t, groupName, group.GroupName)

		t.Logf("Created group: ID=%d Name=%s", group.GroupID, group.GroupName)

		ctx.TrackResourceByType("UserGroup", groupName, func() error {
			return ugSvc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: group.GroupID})
		})
	}, pcloudUserGroups.ServiceConfig)
}

// TestUserGroupLifecycle tests create → get → update → delete for a Vault user group.
func TestUserGroupLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: User Group Lifecycle")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		groupName := framework.RandomResourceName("e2e-group")

		// 1. CREATE
		t.Logf("Step 1: Creating user group [%s]", groupName)
		group, err := ugSvc.Create(&usergroupsmodels.IdsecPCloudAddUserGroup{
			GroupName:   groupName,
			Description: "initial description",
			Location:    "\\",
		})
		require.NoError(t, err, "Failed to create user group")
		require.NotNil(t, group)
		assert.NotZero(t, group.GroupID)

		// Step 4 deletes the group as the test's final assertion, but it still needs a registered
		// cleanup to cover a failure before then. Cleanups cannot be deregistered, so the closure
		// tracks whether the group is already gone: a second delete answers 404 and teardown
		// reports that as a test failure.
		groupDeleted := false
		ctx.TrackResourceByType("UserGroup", groupName, func() error {
			if groupDeleted {
				return nil
			}
			return ugSvc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: group.GroupID})
		})

		// 2. GET
		t.Logf("Step 2: Getting user group [%d]", group.GroupID)
		fetched, err := ugSvc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupID: group.GroupID})
		require.NoError(t, err, "Failed to get user group")
		require.NotNil(t, fetched)
		assert.Equal(t, group.GroupID, fetched.GroupID)
		assert.Equal(t, groupName, fetched.GroupName)

		// 3. UPDATE
		updatedName := groupName + "-updated"
		t.Logf("Step 3: Updating user group [%d] name to [%s]", group.GroupID, updatedName)
		updated, err := ugSvc.Update(&usergroupsmodels.IdsecPCloudUpdateUserGroup{
			GroupID:     group.GroupID,
			GroupName:   updatedName,
			Description: "updated description",
			Location:    "\\",
		})
		require.NoError(t, err, "Failed to update user group")
		require.NotNil(t, updated)
		assert.Equal(t, updatedName, updated.GroupName)

		// 4. DELETE
		t.Logf("Step 4: Deleting user group [%d]", group.GroupID)
		err = ugSvc.Delete(&usergroupsmodels.IdsecPCloudDeleteUserGroup{GroupID: group.GroupID})
		require.NoError(t, err, "Failed to delete user group")
		groupDeleted = true
		t.Log("User group deleted successfully")
	}, pcloudUserGroups.ServiceConfig)
}

// TestGetNonExistentUserGroup verifies that getting a non-existent group returns an error.
func TestGetNonExistentUserGroup(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Get Non-Existent User Group")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		_, err = ugSvc.Get(&usergroupsmodels.IdsecPCloudGetUserGroup{GroupID: 999999999})
		require.Error(t, err, "Expected error when getting non-existent user group")
		t.Logf("Got expected error: %v", err)
	}, pcloudUserGroups.ServiceConfig)
}

// TestUserGroupMemberSelfProvisioning tests adding a member to a self-provisioned group.
// No env vars required — creates both the group and the user.
func TestUserGroupMemberSelfProvisioning(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: User Group Member Self-Provisioning")

		ugSvc, err := ctx.API.PcloudUsergroups()
		require.NoError(t, err, "Failed to get PCloud UserGroups service")

		// Self-provision: create group and user
		group := createTestUserGroup(t, ctx)
		user := createTestUser(t, ctx)

		t.Logf("Adding user [%s] to group [%d]", user.Username, group.GroupID)
		member, err := ugSvc.AddMember(&usergroupsmodels.IdsecPCloudAddUserGroupMember{
			GroupID:    group.GroupID,
			MemberName: user.Username,
			MemberType: "Vault",
		})
		require.NoError(t, err, "Failed to add user to group")
		require.NotNil(t, member)
		assert.Equal(t, group.GroupID, member.GroupID)
		assert.Equal(t, user.Username, member.MemberName)

		// Cleanup membership before group/user cleanup
		ctx.TrackResourceByType("UserGroupMember", fmt.Sprintf("%d/%s", group.GroupID, user.Username), func() error {
			return ugSvc.DeleteMember(&usergroupsmodels.IdsecPCloudDeleteUserGroupMember{
				GroupID:    group.GroupID,
				MemberName: user.Username,
			})
		})
	}, pcloudUserGroups.ServiceConfig)
}
