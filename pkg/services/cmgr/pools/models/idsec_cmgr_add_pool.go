package models

// IdsecCmgrAddPool is a struct representing the filter for adding a pool in the Idsec CMGR service.
type IdsecCmgrAddPool struct {
	Name               string   `json:"name" mapstructure:"name" flag:"name" desc:"The name of the pool to add." required:"true"`
	Description        string   `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"The pool description."`
	AssignedNetworkIDs []string `json:"assigned_network_ids" mapstructure:"assigned_network_ids" flag:"assigned-network-ids" desc:"The networks assigned to the pool."`
}
