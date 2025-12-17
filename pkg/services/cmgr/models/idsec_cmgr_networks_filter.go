package models

// IdsecCmgrNetworksFilter is a struct representing the filter for networks in the Idsec CMGR service.
type IdsecCmgrNetworksFilter struct {
	IdsecCmgrPoolsCommonFilter `mapstructure:",squash"`
}
