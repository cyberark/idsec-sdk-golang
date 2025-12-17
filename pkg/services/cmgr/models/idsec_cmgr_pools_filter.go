package models

// IdsecCmgrPoolsFilter is a struct representing the filter for pools in the Idsec CMGR service.
type IdsecCmgrPoolsFilter struct {
	IdsecCmgrPoolsCommonFilter `mapstructure:",squash"`
}
