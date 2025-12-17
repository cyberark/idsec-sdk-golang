package actions

import directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"

// ActionToSchemaMap is a map that defines the mapping between Directories action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list-directories":          &directoriesmodels.IdsecIdentityListDirectories{},
	"list-directories-entities": &directoriesmodels.IdsecIdentityListDirectoriesEntities{},
	"tenant-default-suffix":     nil,
}
