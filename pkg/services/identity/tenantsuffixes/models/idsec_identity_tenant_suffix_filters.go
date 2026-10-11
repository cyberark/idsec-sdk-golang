// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityTenantSuffixFilters holds the filters for listing TenantSuffixes.
type IdsecIdentityTenantSuffixFilters struct {
	ReplaceDomain string `json:"suffix,omitempty" mapstructure:"suffix" flag:"suffix" desc:"Return only the suffix that matches this value, compared case-insensitively. Omit it to list every suffix."`
}
