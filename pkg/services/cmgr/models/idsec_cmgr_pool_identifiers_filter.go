package models

// IdsecCmgrPoolIdentifiersFilter is a struct representing the filter for pool identifiers in the Idsec CMGR service.
type IdsecCmgrPoolIdentifiersFilter struct {
	IdsecCmgrListPoolIdentifiers `mapstructure:",squash"`
	IdsecCmgrPoolsCommonFilter   `mapstructure:",squash"`
}
