package models

// IdsecCmgrGetPool is a struct representing the filter for getting a specific pool in the Idsec CMGR service.
type IdsecCmgrGetPool struct {
	PoolID string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"The ID of the pool to get."`
}
