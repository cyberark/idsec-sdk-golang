package models

// IdsecCmgrNetworkPool is a struct representing a network pool in the Idsec CMGR service.
type IdsecCmgrNetworkPool struct {
	PoolID string `json:"pool_id" mapstructure:"pool_id" flag:"pool-id" desc:"The ID of the pool."`
	Name   string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the pool."`
}

// IdsecCmgrNetwork is a struct representing a network in the Idsec CMGR service.
type IdsecCmgrNetwork struct {
	NetworkID     string                 `json:"network_id" mapstructure:"network_id" flag:"network-id" desc:"The ID of the network."`
	Name          string                 `json:"name" mapstructure:"name" flag:"name" desc:"The name of the network."`
	AssignedPools []IdsecCmgrNetworkPool `json:"assigned_pools,omitempty" mapstructure:"assigned_pools,omitempty" flag:"assigned-pools" desc:"The pools assigned to the network."`
	CreatedAt     string                 `json:"created_at" mapstructure:"created_at" flag:"created-at" desc:"The creation time of the network."`
	UpdatedAt     string                 `json:"updated_at" mapstructure:"updated_at" flag:"updated-at" desc:"The last update time of the network."`
}
