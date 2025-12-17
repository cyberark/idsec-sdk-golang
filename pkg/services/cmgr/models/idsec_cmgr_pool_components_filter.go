package models

// IdsecCmgrPoolComponentsFilter is a struct representing the filter for pool components in the Idsec CMGR service.
type IdsecCmgrPoolComponentsFilter struct {
	IdsecCmgrPoolsCommonFilter `mapstructure:",squash"`
}
