// Package models contains the request and response types for the identity-securezones service.
package models

// IdsecIdentityDeleteSecureZone is the lookup model for the delete operation.
type IdsecIdentityDeleteSecureZone struct {
	ID string `json:"secure_zone_id" mapstructure:"secure_zone_id" flag:"secure-zone-id" desc:"Server-assigned UUID of the secure zone." validate:"required,min=1"`
}
