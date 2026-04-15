package actions

import componentsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolcomponents/models"

// ActionToSchemaMap is a map that defines the mapping between CMGR pool-components action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"list":    nil,
	"list-by": &componentsmodels.IdsecCmgrPoolComponentsFilter{},
	"get":     &componentsmodels.IdsecCmgrGetPoolComponent{},
}
