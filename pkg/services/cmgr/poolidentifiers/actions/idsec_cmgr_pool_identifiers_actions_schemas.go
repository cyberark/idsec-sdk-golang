package actions

import identifiersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers/models"

// ActionToSchemaMap is a map that defines the mapping between CMGR pool-identifiers action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":      &identifiersmodels.IdsecCmgrAddPoolSingleIdentifier{},
	"bulk-create": &identifiersmodels.IdsecCmgrAddPoolBulkIdentifier{},
	"update":      &identifiersmodels.IdsecCmgrUpdatePoolIdentifier{},
	"delete":      &identifiersmodels.IdsecCmgrDeletePoolSingleIdentifier{},
	"bulk-delete": &identifiersmodels.IdsecCmgrDeletePoolBulkIdentifier{},
	"list":        &identifiersmodels.IdsecCmgrListPoolIdentifiers{},
	"list-by":     &identifiersmodels.IdsecCmgrPoolIdentifiersFilter{},
	"get":         &identifiersmodels.IdsecCmgrGetPoolIdentifier{},
}
