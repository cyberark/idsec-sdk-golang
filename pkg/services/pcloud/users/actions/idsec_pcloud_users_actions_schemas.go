package actions

import usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users/models"

// ActionToSchemaMap maps pCloud Users action names to their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create": &usersmodels.IdsecPCloudAddUser{},
	"get":    &usersmodels.IdsecPCloudGetUser{},
	"update": &usersmodels.IdsecPCloudUpdateUser{},
	"delete": &usersmodels.IdsecPCloudDeleteUser{},
}
