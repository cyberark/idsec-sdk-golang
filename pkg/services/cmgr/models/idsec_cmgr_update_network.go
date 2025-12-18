package models

// IdsecCmgrUpdateNetwork is a struct representing the request to update a network in the Idsec CMGR service.
type IdsecCmgrUpdateNetwork struct {
	NetworkID string `json:"network_id" mapstructure:"network_id" flag:"network-id" desc:"The ID of the network to update."`
	Name      string `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The new name of the network to update."`
}
