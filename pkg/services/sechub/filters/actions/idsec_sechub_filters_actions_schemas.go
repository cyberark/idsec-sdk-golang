package actions

import filtersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub filters action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"get":    &filtersmodels.IdsecSecHubGetFilter{},
	"list":   &filtersmodels.IdsecSecHubGetFilters{},
	"create": &filtersmodels.IdsecSecHubCreateFilter{},
	"delete": &filtersmodels.IdsecSecHubDeleteFilter{},
}
