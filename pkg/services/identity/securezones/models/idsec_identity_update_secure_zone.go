// Package models contains the request and response types for the identity-securezones service.
package models

// IdsecIdentityUpdateSecureZone is the write model for the update operation.
type IdsecIdentityUpdateSecureZone struct {
	ID     string `json:"secure_zone_id" mapstructure:"secure_zone_id" flag:"secure-zone-id" desc:"Server-assigned UUID of the secure zone." validate:"required,min=1"`
	Label  string `json:"label" mapstructure:"label" flag:"label" desc:"Display name of the secure zone. Must be unique across the tenant." validate:"required,min=1"`
	Range  string `json:"ip_range" mapstructure:"ip_range" flag:"ip-range" desc:"IP address or CIDR range covered by this secure zone (e.g. \"192.0.2.0/24\"). The server normalises the value to lowercase." validate:"required,min=1"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"Whether this secure zone is active or inactive. Omit to leave the current status unchanged." choices:"active,inactive" validate:"omitempty,oneof=active inactive"`
}
