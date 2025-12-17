package actions

import (
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
)

// ActionToSchemaMap is a map that defines the mapping between Roles action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-user-to-role":         &rolesmodels.IdsecIdentityAddUserToRole{},
	"add-group-to-role":        &rolesmodels.IdsecIdentityAddGroupToRole{},
	"add-role-to-role":         &rolesmodels.IdsecIdentityAddRoleToRole{},
	"remove-user-from-role":    &rolesmodels.IdsecIdentityRemoveUserFromRole{},
	"remove-group-from-role":   &rolesmodels.IdsecIdentityRemoveGroupFromRole{},
	"remove-role-from-role":    &rolesmodels.IdsecIdentityRemoveRoleFromRole{},
	"create-role":              &rolesmodels.IdsecIdentityCreateRole{},
	"update-role":              &rolesmodels.IdsecIdentityUpdateRole{},
	"delete-role":              &rolesmodels.IdsecIdentityDeleteRole{},
	"list-role-members":        &rolesmodels.IdsecIdentityListRoleMembers{},
	"add-admin-rights-to-role": &rolesmodels.IdsecIdentityAddAdminRightsToRole{},
	"role-id-by-name":          &rolesmodels.IdsecIdentityRoleIDByName{},
}
