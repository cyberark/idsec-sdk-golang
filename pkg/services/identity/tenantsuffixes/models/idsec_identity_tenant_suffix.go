// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityTenantSuffix is the API response model and the Terraform state schema.
type IdsecIdentityTenantSuffix struct {
	ID            string `json:"id" mapstructure:"id" flag:"id" desc:"The server's key for the suffix. It equals the suffix on most tenants and is <tenant-id>.<suffix> where the server namespaces suffixes per tenant. It changes when the suffix is renamed."`
	ReplaceDomain string `json:"suffix" mapstructure:"suffix" flag:"suffix" desc:"The tenant login suffix, for example example.com. Users sign in as name@suffix. The server trims surrounding whitespace and otherwise stores the value as written, so it reads back in the same spelling." validate:"required"`
}
