package models

import poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"

// IdsecCmgrNetworksFilter is a struct representing the filter for networks in the Idsec CMGR service.
type IdsecCmgrNetworksFilter struct {
	poolsmodels.IdsecCmgrPoolsCommonFilter `mapstructure:",squash"`
}
