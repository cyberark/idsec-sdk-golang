package models

// IdsecCmgrGetPoolIdentifier is a struct representing the filter for getting a specific component in a pool in the Idsec CMGR service.
type IdsecCmgrGetPoolIdentifier struct {
	IdentifierID string `json:"identifier_id" mapstructure:"identifier_id" flag:"identifier-id" desc:"The ID of the identifier to get from the pool."`
	PoolID       string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"The ID of the pool to get."`
}
