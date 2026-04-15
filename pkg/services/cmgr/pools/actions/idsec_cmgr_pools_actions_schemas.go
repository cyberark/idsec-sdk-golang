package actions

import poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"

// ActionToSchemaMap is a map that defines the mapping between CMGR pools action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &poolsmodels.IdsecCmgrAddPool{},
	"update":  &poolsmodels.IdsecCmgrUpdatePool{},
	"delete":  &poolsmodels.IdsecCmgrDeletePool{},
	"list":    nil,
	"list-by": &poolsmodels.IdsecCmgrPoolsFilter{},
	"get":     &poolsmodels.IdsecCmgrGetPool{},
	"stats":   nil,
}
