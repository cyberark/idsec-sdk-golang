package actions

import (
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
)

// ActionToSchemaMap is a map that defines the mapping between Auth Profiles action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create-auth-profile":   &authprofilesmodels.IdsecIdentityCreateAuthProfile{},
	"update-auth-profile":   &authprofilesmodels.IdsecIdentityUpdateAuthProfile{},
	"delete-auth-profile":   &authprofilesmodels.IdsecIdentityDeleteAuthProfile{},
	"auth-profile":          &authprofilesmodels.IdsecIdentityGetAuthProfile{},
	"list-auth-profiles":    nil,
	"list-auth-profiles-by": &authprofilesmodels.IdsecIdentityAuthProfilesFilters{},
	"auth-profiles-stats":   nil,
}
