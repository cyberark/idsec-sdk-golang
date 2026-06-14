//go:build (e2e && pamsh) || e2e

package pamsh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pamshsafes "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

var pamshPredefinedPermissionSets = []struct {
	name          string
	permissionSet string
	safePrefix    string
}{
	{name: "connect_only", permissionSet: safesmodels.ConnectOnly, safePrefix: "e2e-pamsh-perm-co"},
	{name: "read_only", permissionSet: safesmodels.ReadOnly, safePrefix: "e2e-pamsh-perm-ro"},
	{name: "approver", permissionSet: safesmodels.Approver, safePrefix: "e2e-pamsh-perm-ap"},
	{name: "accounts_manager", permissionSet: safesmodels.AccountsManager, safePrefix: "e2e-pamsh-perm-am"},
	{name: "full", permissionSet: safesmodels.Full, safePrefix: "e2e-pamsh-perm-fl"},
}

// TestCreateAndUpdateSafeMembers verifies that pamsh can add, update, and get a safe member via PVWA.
func TestCreateAndUpdateSafeMembers(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Create, Update, and Get pamsh Safe Members")

		safesSvc := pamshSafesService(t, ctx)
		safe := createPamshTestSafe(t, ctx, "E2E PAMSH safe members create/update", "e2e-pamsh-sfm-sf")
		t.Logf("Safe created: %s (ID: %s)", safe.SafeName, safe.SafeID)

		expectedMemberName := pamshSafeMemberName(t)
		t.Logf("Adding safe member to %q: %s", safe.SafeName, expectedMemberName)

		member, err := safesSvc.AddMember(&safesmodels.IdsecPamshAddSafeMember{
			SafeID:        safe.SafeID,
			MemberName:    expectedMemberName,
			MemberType:    safesmodels.User,
			PermissionSet: safesmodels.ReadOnly,
		})
		if err != nil {
			errMsg := err.Error()
			low := strings.ToLower(errMsg)
			if strings.Contains(low, "not found") || strings.Contains(low, "does not exist") {
				t.Skipf("Skipping test: '%s' does not exist in environment (%v)", expectedMemberName, err)
			}
			if strings.Contains(low, "already a member") || strings.Contains(errMsg, "409") {
				t.Logf("Member '%s' already in safe, verifying via GetMember...", expectedMemberName)
				existingMember, verifyErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
					SafeID:     safe.SafeID,
					MemberName: expectedMemberName,
				})
				if verifyErr == nil && existingMember != nil {
					member = existingMember
					t.Logf("Verified existing member: %s (%s)", member.MemberName, member.PermissionSet)
					trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, expectedMemberName)
				} else {
					t.Logf("Could not verify existing member: %v", verifyErr)
				}
			} else {
				require.NoError(t, err, "Failed to add pamsh safe member")
			}
		} else {
			require.NotNil(t, member)
			t.Logf("Member added: %s (%s)", member.MemberName, member.PermissionSet)
			trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, expectedMemberName)
		}

		if member != nil {
			t.Logf("Step: Updating safe member %q permission set to %s", expectedMemberName, safesmodels.Approver)
			updatedMember, updateErr := safesSvc.UpdateMember(&safesmodels.IdsecPamshUpdateSafeMember{
				SafeID:        safe.SafeID,
				MemberName:    expectedMemberName,
				PermissionSet: safesmodels.Approver,
			})
			require.NoError(t, updateErr, "Failed to update pamsh safe member")
			require.NotNil(t, updatedMember)
			assert.True(t, strings.EqualFold(safesmodels.Approver, updatedMember.PermissionSet),
				"UpdateMember should return approver permission set, got %q", updatedMember.PermissionSet)

			afterUpdate, getErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
				SafeID:     safe.SafeID,
				MemberName: expectedMemberName,
			})
			require.NoError(t, getErr, "Failed to get pamsh safe member after update")
			require.NotNil(t, afterUpdate)
			assert.True(t, strings.EqualFold(safesmodels.Approver, afterUpdate.PermissionSet),
				"GetMember after update should show approver, got %q", afterUpdate.PermissionSet)
		}

	}, pamshsafes.ServiceConfig)
}

// TestSafeMemberPermissionSets verifies each predefined permission set round-trips via PVWA.
func TestSafeMemberPermissionSets(t *testing.T) {
	for _, tc := range pamshPredefinedPermissionSets {
		t.Run(tc.name, func(t *testing.T) {
			framework.Run(t, func(ctx *framework.TestContext) {
				framework.LogSection(t, "Test: Safe Member Permission Set — "+tc.permissionSet)

				safesSvc := pamshSafesService(t, ctx)
				safe := createPamshTestSafe(t, ctx, "E2E PAMSH permission set "+tc.permissionSet, tc.safePrefix)
				memberName := pamshSafeMemberName(t)

				member, err := safesSvc.AddMember(&safesmodels.IdsecPamshAddSafeMember{
					SafeID:        safe.SafeID,
					MemberName:    memberName,
					MemberType:    safesmodels.User,
					PermissionSet: tc.permissionSet,
				})
				if err != nil {
					if skip, reason := pamshSafeMemberAddErrorSkippable(err); skip {
						t.Skipf("Skipping subtest: %s (%v)", reason, err)
					}
					if strings.Contains(strings.ToLower(err.Error()), "already a member") || strings.Contains(err.Error(), "409") {
						existingMember, verifyErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
							SafeID:     safe.SafeID,
							MemberName: memberName,
						})
						require.NoError(t, verifyErr)
						member = existingMember
					} else {
						require.NoError(t, err, "Failed to add pamsh safe member with %s", tc.permissionSet)
					}
				}
				require.NotNil(t, member)
				trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, memberName)

				assertPamshMemberPermissionSet(t, member, tc.permissionSet)

				got, getErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
					SafeID:     safe.SafeID,
					MemberName: memberName,
				})
				require.NoError(t, getErr, "Failed to get pamsh safe member after add")
				assertPamshMemberPermissionSet(t, got, tc.permissionSet)

				updated, updateErr := safesSvc.UpdateMember(&safesmodels.IdsecPamshUpdateSafeMember{
					SafeID:        safe.SafeID,
					MemberName:    memberName,
					PermissionSet: tc.permissionSet,
				})
				require.NoError(t, updateErr, "Failed to update pamsh safe member with %s", tc.permissionSet)
				assertPamshMemberPermissionSet(t, updated, tc.permissionSet)

				afterUpdate, getAfterErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
					SafeID:     safe.SafeID,
					MemberName: memberName,
				})
				require.NoError(t, getAfterErr, "Failed to get pamsh safe member after update")
				assertPamshMemberPermissionSet(t, afterUpdate, tc.permissionSet)

				t.Logf("Permission set %q verified successfully", tc.permissionSet)
			}, pamshsafes.ServiceConfig)
		})
	}
}

// TestSafeMemberCustomPermissions verifies custom permission flags round-trip via PVWA.
func TestSafeMemberCustomPermissions(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Safe Member Custom Permissions")

		safesSvc := pamshSafesService(t, ctx)
		safe := createPamshTestSafe(t, ctx, "E2E PAMSH custom safe member permissions", "e2e-pamsh-cust")
		memberName := pamshSafeMemberName(t)

		customPerms := safesmodels.IdsecPamshSafeMemberPermissions{
			ListAccounts:              true,
			ViewSafeMembers:           true,
			AccessWithoutConfirmation: true,
			RetrieveAccounts:          true,
		}

		member, err := safesSvc.AddMember(&safesmodels.IdsecPamshAddSafeMember{
			SafeID:        safe.SafeID,
			MemberName:    memberName,
			MemberType:    safesmodels.User,
			PermissionSet: safesmodels.Custom,
			Permissions:   &customPerms,
		})
		if err != nil {
			if skip, reason := pamshSafeMemberAddErrorSkippable(err); skip {
				t.Skipf("Skipping test: %s (%v)", reason, err)
			}
			require.NoError(t, err, "Failed to add pamsh safe member with custom permissions")
		}
		require.NotNil(t, member)
		trackPamshSafeMemberDelete(t, ctx, safesSvc, safe.SafeID, memberName)

		assertPamshMemberCustomPermissions(t, member, customPerms)

		got, getErr := safesSvc.GetMember(&safesmodels.IdsecPamshGetSafeMember{
			SafeID:     safe.SafeID,
			MemberName: memberName,
		})
		require.NoError(t, getErr, "Failed to get pamsh safe member with custom permissions")
		assertPamshMemberCustomPermissions(t, got, customPerms)

		t.Log("Custom permissions verified successfully")
	}, pamshsafes.ServiceConfig)
}
