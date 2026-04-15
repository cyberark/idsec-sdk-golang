//go:build (e2e && pcloud) || e2e

package pcloud

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	safes "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// TestListSafeMembers verifies that we can list members of a safe.
func TestListSafeMembers(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: List Safe Members")

		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// Create a test safe first
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating test safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Test safe for member operations",
		})
		require.NoError(t, err)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// List members
		t.Logf("Listing members of safe: %s", safe.SafeID)
		membersChan, err := safesSvc.ListMembers(&safesmodels.IdsecPCloudListSafeMembers{
			SafeID: safe.SafeID,
		})
		require.NoError(t, err, "Failed to list safe members")

		// Count members
		memberCount := 0
		for page := range membersChan {
			memberCount += len(page.Items)
			for _, member := range page.Items {
				t.Logf("  Member: %s (Type: %s, PermissionSet: %s)",
					member.MemberName, member.MemberType, member.PermissionSet)
			}
		}

		t.Logf("Found %d member(s) in safe", memberCount)
		// New safes typically have at least the creator as a member
		assert.GreaterOrEqual(t, memberCount, 1, "Expected at least one member (creator)")
	}, safes.ServiceConfig)
}

// TestAddAndDeleteSafeMember tests adding and removing a safe member.
func TestAddAndDeleteSafeMember(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Add and Delete Safe Member")

		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// Create a test safe
		safeName := framework.RandomResourceName("e2e-safe")
		t.Logf("Creating test safe: %s", safeName)

		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Test safe for member operations",
		})
		require.NoError(t, err)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Check if Auditors group exists first
		memberName := "Auditors" // Common built-in group
		t.Logf("Checking if member '%s' already exists in safe", memberName)

		existingMember, err := safesSvc.GetMember(&safesmodels.IdsecPCloudGetSafeMember{
			SafeID:     safe.SafeID,
			MemberName: memberName,
		})

		if err == nil && existingMember != nil {
			// Member already exists (auto-added by safe creation)
			t.Logf("⚠ Member '%s' already exists in safe (auto-added as pre-defined owner)", memberName)
			t.Logf("  Existing permissions: %s", existingMember.PermissionSet)

			// Assert that we get an error when trying to add an existing member
			t.Log("Attempting to add existing member (should fail)...")
			_, addErr := safesSvc.AddMember(&safesmodels.IdsecPCloudAddSafeMember{
				SafeID:        safe.SafeID,
				MemberName:    memberName,
				MemberType:    "Group",
				PermissionSet: safesmodels.ReadOnly,
			})

			// We expect this to fail with 409 conflict
			assert.Error(t, addErr, "Adding existing member should fail")
			if addErr != nil {
				assert.Contains(t, addErr.Error(), "already a member", "Error should indicate member already exists")
				t.Logf("✓ Got expected error: %v", addErr)
			}

			// Verify we cannot delete pre-defined owner
			t.Log("Attempting to delete pre-defined owner (should fail)...")
			deleteErr := safesSvc.DeleteMember(&safesmodels.IdsecPCloudDeleteSafeMember{
				SafeID:     safe.SafeID,
				MemberName: memberName,
			})

			// We expect this to fail with 403 forbidden
			assert.Error(t, deleteErr, "Deleting pre-defined owner should fail")
			if deleteErr != nil {
				assert.Contains(t, deleteErr.Error(), "pre-defined Owner", "Error should indicate pre-defined owner")
				t.Logf("✓ Got expected error: %v", deleteErr)
			}

			t.Log("✓ Test completed: Verified Auditors is a protected pre-defined owner")
			return
		}

		// Member doesn't exist, try to add it
		t.Logf("Adding member '%s' to safe with ReadOnly permissions", memberName)
		member, err := safesSvc.AddMember(&safesmodels.IdsecPCloudAddSafeMember{
			SafeID:        safe.SafeID,
			MemberName:    memberName,
			MemberType:    "Group",
			PermissionSet: safesmodels.ReadOnly,
		})

		if err != nil {
			if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "does not exist") {
				t.Skipf("Skipping test: Member '%s' does not exist in this environment", memberName)
				return
			}
			require.NoError(t, err, "Failed to add safe member")
		}

		require.NotNil(t, member)
		assert.Equal(t, memberName, member.MemberName)
		assert.Equal(t, safesmodels.ReadOnly, member.PermissionSet)

		t.Logf("Member added successfully: %s", member.MemberName)

		// Register cleanup for member
		ctx.TrackResourceByType("SafeMember", memberName, func() error {
			t.Logf("Cleaning up safe member: %s", memberName)
			return safesSvc.DeleteMember(&safesmodels.IdsecPCloudDeleteSafeMember{
				SafeID:     safe.SafeID,
				MemberName: memberName,
			})
		})

		// Verify member exists
		t.Log("Verifying member exists...")
		retrievedMember, err := safesSvc.GetMember(&safesmodels.IdsecPCloudGetSafeMember{
			SafeID:     safe.SafeID,
			MemberName: memberName,
		})
		require.NoError(t, err, "Failed to retrieve safe member")
		assert.Equal(t, memberName, retrievedMember.MemberName)
		assert.Equal(t, safesmodels.ReadOnly, retrievedMember.PermissionSet)

		t.Log("Safe member verified successfully")
	}, safes.ServiceConfig)
}

// TestSafeMemberPermissionSets tests different permission sets.
func TestSafeMemberPermissionSets(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Safe Member Permission Sets")

		safesSvc, err := ctx.API.PcloudSafes()
		require.NoError(t, err)

		// Create a test safe
		safeName := framework.RandomResourceName("e2e-safe")
		safe, err := safesSvc.Create(&safesmodels.IdsecPCloudAddSafe{
			SafeName:    safeName,
			Description: "Test safe for permission sets",
		})
		require.NoError(t, err)

		ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
			return safesSvc.Delete(&safesmodels.IdsecPCloudDeleteSafe{
				SafeID: safe.SafeID,
			})
		})

		// Check if Auditors already exists (auto-added by safe creation)
		memberName := "Auditors"

		t.Logf("Checking if member '%s' already exists in safe", memberName)
		existingMember, checkErr := safesSvc.GetMember(&safesmodels.IdsecPCloudGetSafeMember{
			SafeID:     safe.SafeID,
			MemberName: memberName,
		})

		if checkErr == nil && existingMember != nil {
			// Member already exists as pre-defined owner, skip this test
			t.Logf("⚠ Member '%s' already exists as pre-defined owner with '%s' permissions",
				memberName, existingMember.PermissionSet)
			t.Skip("Skipping test: Cannot modify pre-defined owner permissions")
			return
		}

		// Member doesn't exist, proceed with test
		// Test different permission sets
		permissionSets := []string{
			safesmodels.ReadOnly,
			safesmodels.Approver,
		}

		for i, permSet := range permissionSets {
			t.Logf("Testing permission set: %s", permSet)

			if i == 0 {
				// Add member with first permission set
				member, err := safesSvc.AddMember(&safesmodels.IdsecPCloudAddSafeMember{
					SafeID:        safe.SafeID,
					MemberName:    memberName,
					MemberType:    "Group",
					PermissionSet: permSet,
				})

				if err != nil {
					if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "does not exist") {
						t.Skipf("Skipping test: Member '%s' does not exist", memberName)
						return
					}
					require.NoError(t, err)
				}

				require.NotNil(t, member)
				assert.Equal(t, permSet, member.PermissionSet)

				// Register cleanup
				ctx.TrackResourceByType("SafeMember", memberName, func() error {
					return safesSvc.DeleteMember(&safesmodels.IdsecPCloudDeleteSafeMember{
						SafeID:     safe.SafeID,
						MemberName: memberName,
					})
				})
			} else {
				// Update member with new permission set
				updatedMember, err := safesSvc.UpdateMember(&safesmodels.IdsecPCloudUpdateSafeMember{
					SafeID:        safe.SafeID,
					MemberName:    memberName,
					PermissionSet: permSet,
				})
				require.NoError(t, err, "Failed to update safe member")
				assert.Equal(t, permSet, updatedMember.PermissionSet)
			}

			// Verify permission set
			member, err := safesSvc.GetMember(&safesmodels.IdsecPCloudGetSafeMember{
				SafeID:     safe.SafeID,
				MemberName: memberName,
			})
			require.NoError(t, err)
			assert.Equal(t, permSet, member.PermissionSet)

			t.Logf("Permission set '%s' verified successfully", permSet)
		}
	}, safes.ServiceConfig)
}
