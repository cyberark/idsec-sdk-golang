package models

// IdsecPCloudAccountsFilter represents the filter options for accounts.
type IdsecPCloudAccountsFilter struct {
	Search     string `json:"search,omitempty" mapstructure:"search,omitempty" desc:"A list of keywords to search for in accounts, separated by a space" flag:"search"`
	SearchType string `json:"search_type,omitempty" mapstructure:"search_type,omitempty" desc:"Get accounts with the value specified in the Search parameter (contains or startswith)" flag:"search-type"`
	Sort       string `json:"sort,omitempty" mapstructure:"sort,omitempty" desc:"Sort results by given key. Sort direction by ask (default) or desc. Separate multiple properties with commas, up to three properties." flag:"sort"`
	SafeName   string `json:"safe_name,omitempty" mapstructure:"safe_name,omitempty" desc:"The Safe name to use as filter" flag:"safe-name"`
	Offset     int    `json:"offset,omitempty" mapstructure:"offset,omitempty" desc:"Offset of the first account that is returned in the collection of results" flag:"offset"`
	Limit      int    `json:"limit,omitempty" mapstructure:"limit,omitempty" desc:"The maximum number of returned accounts (up to 1000). When used with Offset, determines the limit of accounts from the first returned account." flag:"limit"`
}
