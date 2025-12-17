package actions

import platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec PCloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list-platforms":             nil,
	"list-platforms-by":          &platformsmodels.IdsecPCloudPlatformsFilter{},
	"platform":                   &platformsmodels.IdsecPCloudGetPlatform{},
	"import-platform":            &platformsmodels.IdsecPCloudImportPlatform{},
	"import-target-platform":     &platformsmodels.IdsecPCloudImportTargetPlatform{},
	"export-platform":            &platformsmodels.IdsecPCloudExportPlatform{},
	"export-target-platform":     &platformsmodels.IdsecPCloudExportTargetPlatform{},
	"platforms-stats":            nil,
	"list-target-platforms":      nil,
	"list-target-platforms-by":   &platformsmodels.IdsecPCloudTargetPlatformsFilter{},
	"target-platform":            &platformsmodels.IdsecPCloudGetTargetPlatform{},
	"activate-target-platform":   &platformsmodels.IdsecPCloudActivateTargetPlatform{},
	"deactivate-target-platform": &platformsmodels.IdsecPCloudDeactivateTargetPlatform{},
	"duplicate-target-platform":  &platformsmodels.IdsecPCloudDuplicateTargetPlatform{},
	"delete-target-platform":     &platformsmodels.IdsecPCloudDeleteTargetPlatform{},
	"target-platforms-stats":     nil,
}
