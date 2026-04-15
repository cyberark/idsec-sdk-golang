package models

import poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"

// IdsecCmgrPoolIdentifiersFilter is a struct representing the filter for pool identifiers in the Idsec CMGR service.
type IdsecCmgrPoolIdentifiersFilter struct {
	IdsecCmgrListPoolIdentifiers           `mapstructure:",squash"`
	poolsmodels.IdsecCmgrPoolsCommonFilter `mapstructure:",squash"`
}
