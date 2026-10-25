// Package models contains the request and response types for the identity-securezones service.
package models

// IdsecIdentitySecureZone is the API response model and the Terraform state schema.
type IdsecIdentitySecureZone struct {
	ID     string `json:"secure_zone_id,omitempty" mapstructure:"secure_zone_id" flag:"secure-zone-id" desc:"Server-assigned UUID of the secure zone."`
	Label  string `json:"label" mapstructure:"label" flag:"label" desc:"Display name of the secure zone. Must be unique across the tenant." validate:"required"`
	Range  string `json:"ip_range" mapstructure:"ip_range" flag:"ip-range" desc:"IP address or CIDR range covered by this secure zone (e.g. \"192.0.2.0/24\"). The server normalises the value to lowercase." validate:"required"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"Whether this secure zone is active or inactive. Defaults to \"active\" when omitted." default:"active" choices:"active,inactive" validate:"omitempty,oneof=active inactive"`
}
