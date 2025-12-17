package models

// IdsecCmgrDeletePool is a struct representing the filter for deleting a specific pool in the Idsec CMGR service.
type IdsecCmgrDeletePool struct {
	PoolID string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"ID of the pool to delete"`
}
