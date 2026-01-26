package models

// IdsecPCloudSafesFilters represents the filters for listing safes.
type IdsecPCloudSafesFilters struct {
	Search string `json:"search,omitempty" mapstructure:"search" desc:"Searches according to the Safe name. Search is performed according to the REST standard (search='search word'). The URL encoding of the Safe name. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space"`
	Sort   string `json:"sort,omitempty" mapstructure:"sort" desc:"Sorts according to the safeName property in ascending order (default) or descending order to control the sort direction"`
	Offset int    `json:"offset,omitempty" mapstructure:"offset" desc:"Offset of the first Safe that is returned in the collection of results"`
	Limit  int    `json:"limit,omitempty" mapstructure:"limit" desc:"The maximum number of Safes that are returned. When used together with the offset parameter, this value determines the number of Safes to return, starting from the first Safe that is returned"`
}
