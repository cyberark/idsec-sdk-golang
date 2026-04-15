package actions

import networksmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks/models"

// ActionToSchemaMap is a map that defines the mapping between CMGR networks action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &networksmodels.IdsecCmgrAddNetwork{},
	"update":  &networksmodels.IdsecCmgrUpdateNetwork{},
	"delete":  &networksmodels.IdsecCmgrDeleteNetwork{},
	"list":    nil,
	"list-by": &networksmodels.IdsecCmgrNetworksFilter{},
	"get":     &networksmodels.IdsecCmgrGetNetwork{},
	"stats":   nil,
}
