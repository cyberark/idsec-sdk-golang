package actions

import safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec Privilege Cloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":            &safesmodels.IdsecPCloudAddSafe{},
	"update":            &safesmodels.IdsecPCloudUpdateSafe{},
	"delete":            &safesmodels.IdsecPCloudDeleteSafe{},
	"get":               &safesmodels.IdsecPCloudGetSafe{},
	"list":              nil,
	"list-by":           &safesmodels.IdsecPCloudSafesFilters{},
	"stats":             nil,
	"add-member":        &safesmodels.IdsecPCloudAddSafeMember{},
	"update-member":     &safesmodels.IdsecPCloudUpdateSafeMember{},
	"delete-member":     &safesmodels.IdsecPCloudDeleteSafeMember{},
	"get-member":        &safesmodels.IdsecPCloudGetSafeMember{},
	"list-members":      &safesmodels.IdsecPCloudListSafeMembers{},
	"list-members-by":   &safesmodels.IdsecPCloudSafeMembersFilters{},
	"members-stats":     &safesmodels.IdsecPCloudGetSafeMembersStats{},
	"all-members-stats": nil,
}
