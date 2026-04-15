package models

// IdsecCmgrPoolsStats is a struct representing the statistics of pools in the Idsec CMGR service.
type IdsecCmgrPoolsStats struct {
	PoolsCount              int                       `json:"pools_count" mapstructure:"pools_count" flag:"pools-count" desc:"The overall number of pools."`
	NetworksCountPerPool    map[string]int            `json:"networks_count_per_pool" mapstructure:"networks_count_per_pool" flag:"networks-count-per-pool" desc:"The number of networks for each pool."`
	IdentifiersCountPerPool map[string]int            `json:"identifiers_count_per_pool" mapstructure:"identifiers_count_per_pool" flag:"identifiers-count-per-pool" desc:"The number of identifiers for each pool."`
	ComponentsCountPerPool  map[string]map[string]int `json:"components_count_per_pool" mapstructure:"components_count_per_pool" flag:"components-count-per-pool" desc:"The number of components for each pool."`
}
