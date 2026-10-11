// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityUpdateTenantSuffix is the write model for the update operation, which renames a suffix.
type IdsecIdentityUpdateTenantSuffix struct {
	ID            string `json:"id" mapstructure:"id" flag:"id" desc:"The server's key for the suffix. It equals the suffix on most tenants and is <tenant-id>.<suffix> where the server namespaces suffixes per tenant. It changes when the suffix is renamed. As input to a rename, the current suffix itself is also accepted." validate:"required"`
	ReplaceDomain string `json:"suffix" mapstructure:"suffix" flag:"suffix" desc:"The new tenant login suffix, for example example.org. Users of the current suffix are moved to the new one." validate:"required,regexp=^[\\p{L}\\p{Mn}\\p{Nd}\\p{Pc}.+'\\-]+$"`
}
