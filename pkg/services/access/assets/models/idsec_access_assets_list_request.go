package models

// IdsecAccessAssetsListAssetsRequest represents the query parameters for listing assets.
type IdsecAccessAssetsListAssetsRequest struct {
	RecentsOnly   bool   `json:"recents_only,omitempty" mapstructure:"recents_only,omitempty" flag:"recents-only" desc:"Filter to show only recently accessed assets" default:"false"`
	FavoritesOnly bool   `json:"favorites_only,omitempty" mapstructure:"favorites_only,omitempty" flag:"favorites-only" desc:"Filter to show only favorite assets" default:"false"`
	AccessMethod  string `json:"access_method,omitempty" mapstructure:"access_method,omitempty" flag:"access-method" desc:"Filter by access method (vaulted or zsp)" choices:"vaulted,zsp"`
	Limit         int    `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"Maximum number of assets to return (1-1000)" default:"1000" validate:"min=1,max=1000"`
	Sort          string `json:"sort,omitempty" mapstructure:"sort,omitempty" flag:"sort" desc:"Sort expression (e.g. address.asc, platformId.desc, lastAccessed.desc)"`
	Search        string `json:"search,omitempty" mapstructure:"search,omitempty" flag:"search" desc:"Search criteria (e.g. address contains 1.2.3.4)"`
}
