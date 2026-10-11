// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityDeleteTenantSuffix is the lookup model for the delete operation.
type IdsecIdentityDeleteTenantSuffix struct {
	ReplaceDomain string `json:"suffix" mapstructure:"suffix" flag:"suffix" desc:"The tenant login suffix, for example example.com. Users sign in as name@suffix. The server trims surrounding whitespace and otherwise stores the value as written, so it reads back in the same spelling." validate:"required"`
}
