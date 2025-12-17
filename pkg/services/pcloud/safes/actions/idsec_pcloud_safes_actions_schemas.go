package actions

import safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec PCloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-safe":             &safesmodels.IdsecPCloudAddSafe{},
	"update-safe":          &safesmodels.IdsecPCloudUpdateSafe{},
	"delete-safe":          &safesmodels.IdsecPCloudDeleteSafe{},
	"safe":                 &safesmodels.IdsecPCloudGetSafe{},
	"list-safes":           nil,
	"list-safes-by":        &safesmodels.IdsecPCloudSafesFilters{},
	"safes-stats":          nil,
	"add-safe-member":      &safesmodels.IdsecPCloudAddSafeMember{},
	"update-safe-member":   &safesmodels.IdsecPCloudUpdateSafeMember{},
	"delete-safe-member":   &safesmodels.IdsecPCloudDeleteSafeMember{},
	"safe-member":          &safesmodels.IdsecPCloudGetSafeMember{},
	"list-safe-members":    &safesmodels.IdsecPCloudListSafeMembers{},
	"list-safe-members-by": &safesmodels.IdsecPCloudSafeMembersFilters{},
	"safe-members-stats":   &safesmodels.IdsecPCloudGetSafeMembersStats{},
	"safes-members-stats":  nil,
}
