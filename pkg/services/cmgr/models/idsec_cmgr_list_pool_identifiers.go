package models

// IdsecCmgrListPoolIdentifiers is a struct representing the filter for listing pool identifiers in the Idsec CMGR service.
type IdsecCmgrListPoolIdentifiers struct {
	PoolID string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"Pool id to get the identifiers for"`
}
