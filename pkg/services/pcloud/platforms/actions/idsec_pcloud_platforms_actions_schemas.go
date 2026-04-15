package actions

import platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec Privilege Cloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list":    nil,
	"list-by": &platformsmodels.IdsecPCloudPlatformsFilter{},
	"get":     &platformsmodels.IdsecPCloudGetPlatform{},
	"import":  &platformsmodels.IdsecPCloudImportPlatform{},
	"export":  &platformsmodels.IdsecPCloudExportPlatform{},
	"stats":   nil,
}
