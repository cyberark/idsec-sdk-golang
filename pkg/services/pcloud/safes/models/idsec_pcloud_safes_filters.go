package models

// IdsecPCloudSafesFilters represents the filters for listing safes.
type IdsecPCloudSafesFilters struct {
	Search string `json:"search,omitempty" mapstructure:"search" desc:"Search by string"`
	Sort   string `json:"sort,omitempty" mapstructure:"sort" desc:"Sort results by given key"`
	Offset int    `json:"offset,omitempty" mapstructure:"offset" desc:"Offset to the safes list"`
	Limit  int    `json:"limit,omitempty" mapstructure:"limit" desc:"Limit of results"`
}
