package models

// IdsecIdentityWebappsCustomTemplatesFilters represents the filters for querying identity webapps custom templates.
type IdsecIdentityWebappsCustomTemplatesFilters struct {
	Search string `json:"search,omitempty" mapstructure:"search" flag:"search" desc:"Search string to use"`
}
