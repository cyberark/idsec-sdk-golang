package models

// IdsecCmgrNetworksStats is a struct representing the statistics of networks in the Idsec CMGR service.
type IdsecCmgrNetworksStats struct {
	NetworksCount        int            `json:"networks_count" mapstructure:"networks_count" flag:"networks-count" desc:"The overall number of networks"`
	PoolsCountPerNetwork map[string]int `json:"pools_count_per_network" mapstructure:"pools_count_per_network" flag:"pools-count-per-network" desc:"The number of pools for each network."`
}
