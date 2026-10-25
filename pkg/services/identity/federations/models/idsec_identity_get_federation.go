// Package models provides the data structures for IDSEC Identity federation operations.
package models

// IdsecIdentityGetFederation is the lookup model for the read operation.
type IdsecIdentityGetFederation struct {
	FederationUUID string `json:"federation_id" mapstructure:"federation_id" flag:"federation-id" desc:"The unique identifier of the federation." validate:"required"`
}
