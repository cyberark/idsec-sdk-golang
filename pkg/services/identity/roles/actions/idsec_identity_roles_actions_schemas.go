package actions

import (
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

// ActionToSchemaMap is a map that defines the mapping between Roles action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create-role":                   &rolesmodels.IdsecIdentityCreateRole{},
	"add-admin-rights-to-role":      &rolesmodels.IdsecIdentityAddAdminRightsToRole{},
	"remove-admin-rights-from-role": &rolesmodels.IdsecIdentityRemoveAdminRightsToRole{},
	"role-admin-rights":             &rolesmodels.IdsecIdentityGetRoleAdminRights{},
	"update-role":                   &rolesmodels.IdsecIdentityUpdateRole{},
	"delete-role":                   &rolesmodels.IdsecIdentityDeleteRole{},
	"list-roles":                    nil,
	"list-roles-by":                 &rolesmodels.IdsecIdentityRolesFilter{},
	"role":                          &rolesmodels.IdsecIdentityGetRole{},
	"roles-stats":                   nil,
	"role-member":                   &rolesmodels.IdsecIdentityGetRoleMember{},
	"list-role-members":             &rolesmodels.IdsecIdentityListRoleMembers{},
	"list-role-members-by":          &rolesmodels.IdsecIdentityRoleMembersFilter{},
	"add-member-to-role":            &rolesmodels.IdsecIdentityAddMemberToRole{},
	"remove-member-from-role":       &rolesmodels.IdsecIdentityRemoveMemberFromRole{},
	"role-members-stats":            &rolesmodels.IdsecIdentityGetRoleMembersStats{},
}
