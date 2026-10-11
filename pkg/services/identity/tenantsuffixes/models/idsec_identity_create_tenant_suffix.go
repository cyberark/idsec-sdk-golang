// Package models provides request and response model types for the Identity tenant suffixes service.
package models

// IdsecIdentityCreateTenantSuffix is the write model for the create operation.
type IdsecIdentityCreateTenantSuffix struct {
	// The regexp is the server's alias NAMING_RULE, ^[\w.+'\-]+$ (TenantAlias.cs:38), with .NET's Unicode \w spelled out.
	ReplaceDomain string `json:"suffix" mapstructure:"suffix" flag:"suffix" desc:"The tenant login suffix, for example example.com. Users sign in as name@suffix. The server trims surrounding whitespace and otherwise stores the value as written, so it reads back in the same spelling." validate:"required,regexp=^[\\p{L}\\p{Mn}\\p{Nd}\\p{Pc}.+'\\-]+$"`
}
