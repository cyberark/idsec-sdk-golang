// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityGetTenantSuffix is the lookup model for the read operation. At least one of the two
// fields must be set; when both are, the key is tried first.
type IdsecIdentityGetTenantSuffix struct {
	ID            string `json:"id,omitempty" mapstructure:"id" flag:"id" desc:"The server's key for the suffix, or the suffix itself. Set this or suffix."`
	ReplaceDomain string `json:"suffix,omitempty" mapstructure:"suffix" flag:"suffix" desc:"The tenant login suffix, for example example.com, compared case-insensitively. Set this or id."`
}
