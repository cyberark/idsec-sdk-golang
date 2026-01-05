package models

// IdsecIdentityRolesFilter represents the filters for querying identity roles.
type IdsecIdentityRolesFilter struct {
	Search       string   `json:"search,omitempty" mapstructure:"search" flag:"search" desc:"Search string to use"`
	AdminRights  []string `json:"admin_rights,omitempty" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights to filter by"`
	PageSize     int      `json:"page_size,omitempty" mapstructure:"page_size" flag:"page-size" desc:"Number of results per page"`
	Limit        int      `json:"limit,omitempty" mapstructure:"limit" flag:"limit" desc:"Maximum number of results to return"`
	MaxPageCount int      `json:"max_page_count,omitempty" mapstructure:"max_page_count" flag:"max-page-count" desc:"Maximum number of pages to retrieve"`
}
