package actions

import (
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

// ActionToSchemaMap is a map that defines the mapping between Roles action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":              &rolesmodels.IdsecIdentityCreateRole{},
	"add-admin-rights":    &rolesmodels.IdsecIdentityAddAdminRightsToRole{},
	"remove-admin-rights": &rolesmodels.IdsecIdentityRemoveAdminRightsToRole{},
	"get-admin-rights":    &rolesmodels.IdsecIdentityGetRoleAdminRights{},
	"update":              &rolesmodels.IdsecIdentityUpdateRole{},
	"delete":              &rolesmodels.IdsecIdentityDeleteRole{},
	"list":                nil,
	"list-by":             &rolesmodels.IdsecIdentityRolesFilter{},
	"get":                 &rolesmodels.IdsecIdentityGetRole{},
	"stats":               nil,
	"get-member":          &rolesmodels.IdsecIdentityGetRoleMember{},
	"list-members":        &rolesmodels.IdsecIdentityListRoleMembers{},
	"list-members-by":     &rolesmodels.IdsecIdentityRoleMembersFilter{},
	"add-member":          &rolesmodels.IdsecIdentityAddMemberToRole{},
	"remove-member":       &rolesmodels.IdsecIdentityRemoveMemberFromRole{},
	"member-stats":        &rolesmodels.IdsecIdentityGetRoleMembersStats{},
}
