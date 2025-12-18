package models

// IdsecCmgrAddNetwork is a struct representing the filter for adding a network in the Idsec CMGR service.
type IdsecCmgrAddNetwork struct {
	Name string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the network to add." required:"true"`
}
