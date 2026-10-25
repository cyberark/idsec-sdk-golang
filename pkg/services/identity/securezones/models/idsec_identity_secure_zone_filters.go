// Package models contains the request and response types for the identity-securezones service.
package models

// IdsecIdentitySecureZoneFilters holds the filters for listing SecureZones.
type IdsecIdentitySecureZoneFilters struct {
	Label  string `json:"label,omitempty" mapstructure:"label" flag:"label" desc:"Filter results by display name (exact match)."`
	Range  string `json:"ip_range,omitempty" mapstructure:"ip_range" flag:"ip-range" desc:"Filter results by IP address or CIDR range (exact match)."`
	Status string `json:"status,omitempty" mapstructure:"status" flag:"status" desc:"Filter results by status: active or inactive." choices:"active,inactive" validate:"omitempty,oneof=active inactive"`
}
