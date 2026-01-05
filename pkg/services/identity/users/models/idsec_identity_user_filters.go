package models

// IdsecIdentityUserFilters represents the filters for querying identity users.
type IdsecIdentityUserFilters struct {
	Search       string `json:"search,omitempty" mapstructure:"search" flag:"search" desc:"Search string to use"`
	PageSize     int    `json:"page_size,omitempty" mapstructure:"page_size" flag:"page-size" desc:"Number of results to return per page"`
	Limit        int    `json:"limit,omitempty" mapstructure:"limit" flag:"limit" desc:"Total number of results to return"`
	MaxPageCount int    `json:"max_page_count,omitempty" mapstructure:"max_page_count" flag:"max-page-count" desc:"Maximum number of pages to retrieve"`
	PageNumber   int    `json:"page_number,omitempty" mapstructure:"page_number" flag:"page-number" desc:"Page number to start from"`
}
