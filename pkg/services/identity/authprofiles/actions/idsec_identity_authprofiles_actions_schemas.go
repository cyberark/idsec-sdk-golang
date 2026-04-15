package actions

import (
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
)

// ActionToSchemaMap is a map that defines the mapping between Auth Profiles action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &authprofilesmodels.IdsecIdentityCreateAuthProfile{},
	"update":  &authprofilesmodels.IdsecIdentityUpdateAuthProfile{},
	"delete":  &authprofilesmodels.IdsecIdentityDeleteAuthProfile{},
	"get":     &authprofilesmodels.IdsecIdentityGetAuthProfile{},
	"list":    nil,
	"list-by": &authprofilesmodels.IdsecIdentityAuthProfilesFilters{},
	"stats":   nil,
}
