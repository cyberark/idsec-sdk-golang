package actions

import targetplatformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/targetplatforms/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec Privilege Cloud target platform action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"import":     &targetplatformsmodels.IdsecPCloudImportTargetPlatform{},
	"export":     &targetplatformsmodels.IdsecPCloudExportTargetPlatform{},
	"list":       nil,
	"list-by":    &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{},
	"get":        &targetplatformsmodels.IdsecPCloudGetTargetPlatform{},
	"activate":   &targetplatformsmodels.IdsecPCloudActivateTargetPlatform{},
	"deactivate": &targetplatformsmodels.IdsecPCloudDeactivateTargetPlatform{},
	"duplicate":  &targetplatformsmodels.IdsecPCloudDuplicateTargetPlatform{},
	"delete":     &targetplatformsmodels.IdsecPCloudDeleteTargetPlatform{},
	"stats":      nil,
}
