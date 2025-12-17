package actions

import cmgrmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/models"

// ActionToSchemaMap is a map that defines the mapping between CMGR action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-network":              &cmgrmodels.IdsecCmgrAddNetwork{},
	"update-network":           &cmgrmodels.IdsecCmgrUpdateNetwork{},
	"delete-network":           &cmgrmodels.IdsecCmgrDeleteNetwork{},
	"list-networks":            nil,
	"list-networks-by":         &cmgrmodels.IdsecCmgrNetworksFilter{},
	"network":                  &cmgrmodels.IdsecCmgrGetNetwork{},
	"networks-stats":           nil,
	"add-pool":                 &cmgrmodels.IdsecCmgrAddPool{},
	"update-pool":              &cmgrmodels.IdsecCmgrUpdatePool{},
	"delete-pool":              &cmgrmodels.IdsecCmgrDeletePool{},
	"list-pools":               nil,
	"list-pools-by":            &cmgrmodels.IdsecCmgrPoolsFilter{},
	"pool":                     &cmgrmodels.IdsecCmgrGetPool{},
	"pools-stats":              nil,
	"add-pool-identifier":      &cmgrmodels.IdsecCmgrAddPoolSingleIdentifier{},
	"add-pool-identifiers":     &cmgrmodels.IdsecCmgrAddPoolBulkIdentifier{},
	"update-pool-identifier":   &cmgrmodels.IdsecCmgrUpdatePoolIdentifier{},
	"delete-pool-identifier":   &cmgrmodels.IdsecCmgrDeletePoolSingleIdentifier{},
	"delete-pool-identifiers":  &cmgrmodels.IdsecCmgrDeletePoolBulkIdentifier{},
	"list-pool-identifiers":    &cmgrmodels.IdsecCmgrListPoolIdentifiers{},
	"list-pool-identifiers-by": &cmgrmodels.IdsecCmgrPoolIdentifiersFilter{},
	"pool-identifier":          &cmgrmodels.IdsecCmgrGetPoolIdentifier{},
	"list-pools-components":    nil,
	"list-pools-components-by": &cmgrmodels.IdsecCmgrPoolComponentsFilter{},
	"pool-component":           &cmgrmodels.IdsecCmgrGetPoolComponent{},
}
