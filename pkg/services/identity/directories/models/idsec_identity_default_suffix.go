package models

// IdsecIdentityTenantSuffixes represents the schema for the tenant suffixes information.
type IdsecIdentityTenantSuffixes struct {
	Suffixes      []string `json:"suffixes" mapstructure:"suffixes" flag:"suffixes" desc:"List of tenant default suffixes."`
	DefaultSuffix string   `json:"default_suffix" mapstructure:"default_suffix" flag:"default-suffix" desc:"The tenant default suffix."`
}
