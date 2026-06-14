package pamshsafes

import (
	"fmt"
	"reflect"

	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
)

// memberPermissionSets maps predefined permission sets to their PVWA permission flags.
var memberPermissionSets = map[string]safesmodels.IdsecPamshSafeMemberPermissions{
	safesmodels.ConnectOnly: {
		ListAccounts: true,
		UseAccounts:  true,
	},
	safesmodels.ReadOnly: {
		ListAccounts:     true,
		UseAccounts:      true,
		RetrieveAccounts: true,
	},
	safesmodels.Approver: {
		ListAccounts:                true,
		ViewSafeMembers:             true,
		ManageSafeMembers:           true,
		RequestsAuthorizationLevel1: true,
	},
	safesmodels.AccountsManager: {
		ListAccounts:                           true,
		UseAccounts:                            true,
		RetrieveAccounts:                       true,
		AddAccounts:                            true,
		UpdateAccountProperties:                true,
		UpdateAccountContent:                   true,
		InitiateCPMAccountManagementOperations: true,
		SpecifyNextAccountContent:              true,
		RenameAccounts:                         true,
		DeleteAccounts:                         true,
		UnlockAccounts:                         true,
		ViewSafeMembers:                        true,
		ManageSafeMembers:                      true,
		ViewAuditLog:                           true,
		AccessWithoutConfirmation:              true,
	},
	safesmodels.Full: {
		ListAccounts:                           true,
		UseAccounts:                            true,
		RetrieveAccounts:                       true,
		AddAccounts:                            true,
		UpdateAccountProperties:                true,
		UpdateAccountContent:                   true,
		InitiateCPMAccountManagementOperations: true,
		SpecifyNextAccountContent:              true,
		RenameAccounts:                         true,
		DeleteAccounts:                         true,
		UnlockAccounts:                         true,
		ViewSafeMembers:                        true,
		ManageSafeMembers:                      true,
		ViewAuditLog:                           true,
		AccessWithoutConfirmation:              true,
		RequestsAuthorizationLevel1:            true,
		ManageSafe:                             true,
		BackupSafe:                             true,
		MoveAccountsAndFolders:                 true,
		CreateFolders:                          true,
		DeleteFolders:                          true,
	},
}

// PermissionsForSet returns the permission flags for a predefined permission set.
func PermissionsForSet(permissionSet string) (safesmodels.IdsecPamshSafeMemberPermissions, bool) {
	permissions, ok := memberPermissionSets[permissionSet]
	return permissions, ok
}

// ResolvePermissionSet maps returned PVWA permissions to a predefined set or custom.
func ResolvePermissionSet(perms safesmodels.IdsecPamshSafeMemberPermissions) string {
	for permissionSet, expected := range memberPermissionSets {
		if reflect.DeepEqual(perms, expected) {
			return permissionSet
		}
	}
	return safesmodels.Custom
}

// PrepareAddMemberPermissions applies defaults and expands predefined permission sets for AddMember.
func PrepareAddMemberPermissions(m *safesmodels.IdsecPamshAddSafeMember) error {
	if m.PermissionSet == "" && m.Permissions == nil {
		m.PermissionSet = safesmodels.ReadOnly
	}
	if m.PermissionSet == safesmodels.Custom && m.Permissions == nil {
		return fmt.Errorf("permission set is custom but permissions are not set")
	}
	if m.PermissionSet == safesmodels.Custom {
		return nil
	}
	permissions, ok := memberPermissionSets[m.PermissionSet]
	if !ok {
		return fmt.Errorf("invalid permission set: %s", m.PermissionSet)
	}
	m.Permissions = &permissions
	return nil
}

// PrepareUpdateMemberPermissions expands predefined permission sets when updating member permissions.
func PrepareUpdateMemberPermissions(m *safesmodels.IdsecPamshUpdateSafeMember) error {
	if m.PermissionSet == "" && m.Permissions == nil {
		return nil
	}
	if m.PermissionSet == safesmodels.Custom {
		return nil
	}
	permissions, ok := memberPermissionSets[m.PermissionSet]
	if !ok {
		return fmt.Errorf("invalid permission set: %s", m.PermissionSet)
	}
	m.Permissions = &permissions
	return nil
}
