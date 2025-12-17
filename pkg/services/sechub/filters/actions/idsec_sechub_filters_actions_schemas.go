package actions

import filtersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub filters action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"filter":        &filtersmodels.IdsecSecHubGetFilter{},
	"list-filters":  &filtersmodels.IdsecSecHubGetFilters{},
	"add-filter":    &filtersmodels.IdsecSecHubAddFilter{},
	"delete-filter": &filtersmodels.IdsecSecHubDeleteFilter{},
}
