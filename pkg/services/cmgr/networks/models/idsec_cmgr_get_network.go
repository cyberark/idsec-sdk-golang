package models

// IdsecCmgrGetNetwork is a struct representing the filter for getting a specific network in the Idsec CMGR service.
type IdsecCmgrGetNetwork struct {
	NetworkID string `json:"network_id" mapstructure:"network_id" flag:"network-id" desc:"The ID of the network to get."`
}
