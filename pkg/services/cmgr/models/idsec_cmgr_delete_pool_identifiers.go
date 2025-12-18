package models

// IdsecCmgrDeletePoolIdentifier is a struct representing the filter for deleting a specific identifier from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolIdentifier struct {
	IdentifierID string `json:"identifier_id" mapstructure:"identifier_id" flag:"identifier-id" desc:"The ID of the identifier to delete."`
}

// IdsecCmgrDeletePoolSingleIdentifier is a struct representing the filter for deleting a single identifier from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolSingleIdentifier struct {
	IdentifierID string `json:"identifier_id" mapstructure:"identifier_id" flag:"identifier-id" desc:"The ID of the identifier to delete."`
	PoolID       string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"The ID of the pool from which to delete the identifiers."`
}

// IdsecCmgrDeletePoolBulkIdentifier is a struct representing the filter for deleting multiple identifiers from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolBulkIdentifier struct {
	PoolID      string                        `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"The ID of the pool from which to delete the identifiers."`
	Identifiers []IdsecCmgrDeletePoolIdentifier `json:"identifiers" mapstructure:"identifiers" flag:"identifiers" desc:"The identifiers to delete."`
}
