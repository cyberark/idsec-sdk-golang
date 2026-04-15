package actions

import usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"

// ActionToSchemaMap is a map that defines the mapping between Users action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":                   &usersmodels.IdsecIdentityCreateUser{},
	"update":                   &usersmodels.IdsecIdentityUpdateUser{},
	"get":                      &usersmodels.IdsecIdentityGetUser{},
	"list":                     nil,
	"list-by":                  &usersmodels.IdsecIdentityUserFilters{},
	"delete":                   &usersmodels.IdsecIdentityDeleteUser{},
	"delete-users":             &usersmodels.IdsecIdentityDeleteUsers{},
	"reset-password":           &usersmodels.IdsecIdentityResetUserPassword{},
	"info":                     nil,
	"stats":                    nil,
	"attributes-schema":        nil,
	"upsert-attributes-schema": &usersmodels.IdsecIdentityUpsertUserAttributesSchema{},
	"delete-attributes-schema": &usersmodels.IdsecIdentityDeleteUserAttributesSchema{},
	"get-attributes":           &usersmodels.IdsecIdentityGetUserAttributes{},
	"upsert-attributes":        &usersmodels.IdsecIdentityUpsertUserAttributes{},
	"delete-attributes":        &usersmodels.IdsecIdentityDeleteUserAttributes{},
}
