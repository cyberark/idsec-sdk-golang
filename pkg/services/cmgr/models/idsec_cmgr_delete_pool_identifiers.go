package models

// IdsecCmgrDeletePoolIdentifier is a struct representing the filter for deleting a specific identifier from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolIdentifier struct {
	IdentifierID string `json:"identifier_id" mapstructure:"identifier_id" flag:"identifier-id" desc:"ID of the identifier to delete"`
}

// IdsecCmgrDeletePoolSingleIdentifier is a struct representing the filter for deleting a single identifier from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolSingleIdentifier struct {
	IdentifierID string `json:"identifier_id" mapstructure:"identifier_id" flag:"identifier-id" desc:"ID of the identifier to delete"`
	PoolID       string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"ID of the pool to delete the identifier from"`
}

// IdsecCmgrDeletePoolBulkIdentifier is a struct representing the filter for deleting multiple identifiers from a pool in the Idsec CMGR service.
type IdsecCmgrDeletePoolBulkIdentifier struct {
	PoolID      string                          `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"ID of the pool to delete the identifiers from"`
	Identifiers []IdsecCmgrDeletePoolIdentifier `json:"identifiers" mapstructure:"identifiers" flag:"identifiers" desc:"Identifiers to delete"`
}
