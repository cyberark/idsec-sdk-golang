package actions

import usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"

// ActionToSchemaMap is a map that defines the mapping between Users action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create-user":         &usersmodels.IdsecIdentityCreateUser{},
	"update-user":         &usersmodels.IdsecIdentityUpdateUser{},
	"user":                &usersmodels.IdsecIdentityGetUser{},
	"list-users":          nil,
	"list-users-by":       &usersmodels.IdsecIdentityUserFilters{},
	"delete-user":         &usersmodels.IdsecIdentityDeleteUser{},
	"delete-users":        &usersmodels.IdsecIdentityDeleteUsers{},
	"reset-user-password": &usersmodels.IdsecIdentityResetUserPassword{},
	"user-info":           nil,
	"users-stats":         nil,
}
