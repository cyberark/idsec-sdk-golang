//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups"
	localgroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/localgroups/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestLocalGroupLifecycle tests create → get → update → delete for a Vault local group.
func TestLocalGroupLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Local Group Lifecycle")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		groupName := framework.RandomResourceName("e2e-localgroup")

		// 1. CREATE
		t.Logf("Step 1: Creating local group [%s]", groupName)
		group, err := lgSvc.Create(&localgroupsmodels.IdsecPCloudAddLocalGroup{
			GroupName:   groupName,
			Description: "e2e test local group",
			Location:    "\\",
		})
		require.NoError(t, err, "Failed to create local group")
		require.NotNil(t, group)
		assert.NotEmpty(t, group.GroupID, "GroupID should be non-empty after Create")
		assert.Equal(t, groupName, group.GroupName)

		t.Logf("Created local group: ID=%s Name=%s", group.GroupID, group.GroupName)

		groupDeleted := false
		ctx.TrackResourceByType("LocalGroup", groupName, func() error {
			if groupDeleted {
				return nil
			}
			return lgSvc.Delete(&localgroupsmodels.IdsecPCloudDeleteLocalGroup{GroupID: group.GroupID})
		})

		// 2. GET by ID
		t.Logf("Step 2: Getting local group [%s]", group.GroupID)
		fetched, err := lgSvc.Get(&localgroupsmodels.IdsecPCloudGetLocalGroup{GroupID: group.GroupID})
		require.NoError(t, err, "Failed to get local group by ID")
		require.NotNil(t, fetched)
		assert.Equal(t, group.GroupID, fetched.GroupID)
		assert.Equal(t, groupName, fetched.GroupName)

		// 3. GET by Name
		t.Logf("Step 3: Getting local group by name [%s]", groupName)
		fetchedByName, err := lgSvc.Get(&localgroupsmodels.IdsecPCloudGetLocalGroup{GroupName: groupName})
		require.NoError(t, err, "Failed to get local group by name")
		require.NotNil(t, fetchedByName)
		assert.Equal(t, group.GroupID, fetchedByName.GroupID)

		// 4. UPDATE
		updatedName := groupName + "-upd"
		t.Logf("Step 4: Updating local group [%s] name to [%s]", group.GroupID, updatedName)
		updated, err := lgSvc.Update(&localgroupsmodels.IdsecPCloudUpdateLocalGroup{
			GroupID:   group.GroupID,
			GroupName: updatedName,
		})
		require.NoError(t, err, "Failed to update local group")
		require.NotNil(t, updated)
		assert.Equal(t, updatedName, updated.GroupName)

		// 5. DELETE
		t.Logf("Step 5: Deleting local group [%s]", group.GroupID)
		err = lgSvc.Delete(&localgroupsmodels.IdsecPCloudDeleteLocalGroup{GroupID: group.GroupID})
		require.NoError(t, err, "Failed to delete local group")
		groupDeleted = true
		t.Log("Local group deleted successfully")
	}, localgroups.ServiceConfig)
}

// TestLocalGroupMemberLifecycle tests the full membership lifecycle: add → get → delete.
// Creates both the group and the member user as part of the test.
func TestLocalGroupMemberLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Local Group Member Lifecycle")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		// Self-provision: create group and user
		group := createTestLocalGroup(t, ctx)
		user := createTestUser(t, ctx)

		// 1. ADD MEMBER
		t.Logf("Step 1: Adding user [%s] to local group [%s]", user.Username, group.GroupID)
		member, err := lgSvc.AddMember(&localgroupsmodels.IdsecPCloudAddLocalGroupMember{
			GroupID:    group.GroupID,
			MemberName: user.Username,
			MemberType: "Vault",
		})
		require.NoError(t, err, "Failed to add member to local group")
		require.NotNil(t, member)
		assert.Equal(t, group.GroupID, member.GroupID)
		assert.Equal(t, user.Username, member.MemberName)

		t.Logf("Member added: memberName=%s groupID=%s", member.MemberName, member.GroupID)

		memberRemoved := false
		ctx.TrackResourceByType("LocalGroupMember", fmt.Sprintf("%s/%s", group.GroupID, user.Username), func() error {
			if memberRemoved {
				return nil
			}
			return lgSvc.DeleteMember(&localgroupsmodels.IdsecPCloudDeleteLocalGroupMember{
				GroupID:    group.GroupID,
				MemberName: user.Username,
			})
		})

		// 2. GET MEMBER
		t.Logf("Step 2: Getting member [%s] of local group [%s]", user.Username, group.GroupID)
		fetchedMember, err := lgSvc.GetMember(&localgroupsmodels.IdsecPCloudGetLocalGroupMember{
			GroupID:    group.GroupID,
			MemberName: user.Username,
		})
		require.NoError(t, err, "Failed to get member")
		require.NotNil(t, fetchedMember)
		assert.Equal(t, group.GroupID, fetchedMember.GroupID)
		assert.Equal(t, user.Username, fetchedMember.MemberName)

		// 3. ADD SECOND MEMBER — MemberType omitted to validate that the "Vault" default is accepted
		// by PVWA (the default was wrong prior to this fix: "User" is rejected by the endpoint).
		secondUser := createTestUser(t, ctx)
		t.Logf("Step 3: Adding second user [%s] without explicit MemberType (must default to Vault)", secondUser.Username)
		secondMember, err := lgSvc.AddMember(&localgroupsmodels.IdsecPCloudAddLocalGroupMember{
			GroupID:    group.GroupID,
			MemberName: secondUser.Username,
			// MemberType intentionally omitted — must default to "Vault"
		})
		require.NoError(t, err, "AddMember with default MemberType should succeed")
		require.NotNil(t, secondMember)
		assert.Equal(t, secondUser.Username, secondMember.MemberName)
		ctx.TrackResourceByType("LocalGroupMember", fmt.Sprintf("%s/%s", group.GroupID, secondUser.Username), func() error {
			return lgSvc.DeleteMember(&localgroupsmodels.IdsecPCloudDeleteLocalGroupMember{
				GroupID:    group.GroupID,
				MemberName: secondUser.Username,
			})
		})

		// 4. DELETE MEMBER
		t.Logf("Step 4: Removing member [%s] from local group [%s]", user.Username, group.GroupID)
		err = lgSvc.DeleteMember(&localgroupsmodels.IdsecPCloudDeleteLocalGroupMember{
			GroupID:    group.GroupID,
			MemberName: user.Username,
		})
		require.NoError(t, err, "DeleteMember should succeed")
		memberRemoved = true
		t.Log("Member removed successfully")
	}, localgroups.ServiceConfig)
}

// TestLocalGroupGetPredefinedGroup verifies that Get with IncludePredefinedUsers=true in
// underlying list call (via Get) can resolve built-in Vault groups.
// Requires IDSEC_E2E_PREDEFINED_GROUP_NAME to be set to a known predefined group name
// (e.g. "Vault Admins").
func TestLocalGroupGetPredefinedGroup(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Get Predefined Local Group")

		groupName := requireEnv(t, "IDSEC_E2E_PREDEFINED_GROUP_NAME")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		t.Logf("Looking up predefined group [%s]", groupName)
		group, err := lgSvc.Get(&localgroupsmodels.IdsecPCloudGetLocalGroup{GroupName: groupName})
		require.NoError(t, err, "Get should find a predefined Vault group when includePredefinedUsers=true is sent")
		require.NotNil(t, group)
		assert.NotEmpty(t, group.GroupID, "Predefined group should have a non-empty GroupID")
		assert.Equal(t, groupName, group.GroupName)
		t.Logf("Found predefined group: ID=%s Name=%s", group.GroupID, group.GroupName)
	}, localgroups.ServiceConfig)
}

// TestLocalGroupEmptyIDGuard verifies that write operations reject an empty GroupID
// before making any network call.
func TestLocalGroupEmptyIDGuard(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Empty GroupID Guard on Write Paths")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		t.Log("Update with empty GroupID")
		_, err = lgSvc.Update(&localgroupsmodels.IdsecPCloudUpdateLocalGroup{GroupID: "", GroupName: "x"})
		require.Error(t, err, "Update must reject empty GroupID")
		assert.Contains(t, err.Error(), "group ID")

		t.Log("Delete with empty GroupID")
		err = lgSvc.Delete(&localgroupsmodels.IdsecPCloudDeleteLocalGroup{GroupID: ""})
		require.Error(t, err, "Delete must reject empty GroupID")
		assert.Contains(t, err.Error(), "group ID")

		t.Log("AddMember with empty GroupID")
		_, err = lgSvc.AddMember(&localgroupsmodels.IdsecPCloudAddLocalGroupMember{GroupID: "", MemberName: "user1"})
		require.Error(t, err, "AddMember must reject empty GroupID")
		assert.Contains(t, err.Error(), "group ID")

		t.Log("DeleteMember with empty GroupID")
		err = lgSvc.DeleteMember(&localgroupsmodels.IdsecPCloudDeleteLocalGroupMember{GroupID: "", MemberName: "user1"})
		require.Error(t, err, "DeleteMember must reject empty GroupID")
		assert.Contains(t, err.Error(), "group ID")
	}, localgroups.ServiceConfig)
}

// TestLocalGroupGetNonExistent verifies that Get returns an error for a non-existent group.
func TestLocalGroupGetNonExistent(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Get Non-Existent Local Group")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		_, err = lgSvc.Get(&localgroupsmodels.IdsecPCloudGetLocalGroup{GroupName: "idsec-e2e-nonexistent-group-xyz"})
		require.ErrorIs(t, err, localgroups.ErrLocalGroupNotFound)
		require.ErrorIs(t, err, common.ErrNotFound, "provider Read handlers depend on the common.ErrNotFound chain")
		t.Logf("Got expected error: %v", err)
	}, localgroups.ServiceConfig)
}

// TestLocalGroupDeleteNonExistentMember verifies that DeleteMember on a non-existent member
// returns an error.
func TestLocalGroupDeleteNonExistentMember(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Delete Non-Existent Local Group Member")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		group := createTestLocalGroup(t, ctx)

		err = lgSvc.DeleteMember(&localgroupsmodels.IdsecPCloudDeleteLocalGroupMember{
			GroupID:    group.GroupID,
			MemberName: "idsec-e2e-nonexistent-member",
		})
		require.Error(t, err, "Expected error when deleting non-existent local group member")
		t.Logf("Got expected error: %v", err)
	}, localgroups.ServiceConfig)
}

// TestLocalGroupUpdateAutoFetchesName verifies that Update succeeds when GroupName is omitted —
// the service must auto-fetch the current name so the required PVWA field is still sent.
func TestLocalGroupUpdateAutoFetchesName(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Update Without GroupName Auto-Fetches Existing Name")

		lgSvc, err := ctx.API.PcloudLocalgroups()
		require.NoError(t, err, "Failed to get PCloud LocalGroups service")

		group := createTestLocalGroup(t, ctx)

		t.Logf("Updating local group [%s] description without supplying GroupName", group.GroupID)
		updated, err := lgSvc.Update(&localgroupsmodels.IdsecPCloudUpdateLocalGroup{
			GroupID:     group.GroupID,
			Description: "updated by e2e test",
			// GroupName intentionally omitted — service must auto-fetch
		})
		require.NoError(t, err, "Update without GroupName should succeed (name auto-fetched)")
		require.NotNil(t, updated)
		assert.Equal(t, group.GroupName, updated.GroupName, "GroupName must be preserved when not supplied")
	}, localgroups.ServiceConfig)
}

// createTestLocalGroup creates a Vault local group and registers automatic cleanup.
func createTestLocalGroup(t *testing.T, ctx *framework.TestContext) *localgroupsmodels.IdsecPCloudLocalGroup {
	t.Helper()

	lgSvc, err := ctx.API.PcloudLocalgroups()
	require.NoError(t, err, "Failed to get PCloud LocalGroups service")

	groupName := framework.RandomResourceName("e2e-localgroup")
	t.Logf("Creating test local group: %s", groupName)

	group, err := lgSvc.Create(&localgroupsmodels.IdsecPCloudAddLocalGroup{
		GroupName:   groupName,
		Description: "e2e test local group",
		Location:    "\\",
	})
	require.NoError(t, err, "Failed to create test local group")

	ctx.TrackResourceByType("LocalGroup", groupName, func() error {
		return lgSvc.Delete(&localgroupsmodels.IdsecPCloudDeleteLocalGroup{GroupID: group.GroupID})
	})

	return group
}
