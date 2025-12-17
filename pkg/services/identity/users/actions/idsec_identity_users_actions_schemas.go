package actions

import usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"

// ActionToSchemaMapIdentityUsers is a map that defines the mapping between Users action names and their corresponding schema types.
var ActionToSchemaMapIdentityUsers = map[string]interface{}{
	"create-user":         &usersmodels.IdsecIdentityCreateUser{},
	"update-user":         &usersmodels.IdsecIdentityUpdateUser{},
	"delete-user":         &usersmodels.IdsecIdentityDeleteUser{},
	"user-by-name":        &usersmodels.IdsecIdentityUserByName{},
	"user-id-by-name":     &usersmodels.IdsecIdentityUserIDByName{},
	"reset-user-password": &usersmodels.IdsecIdentityResetUserPassword{},
}
