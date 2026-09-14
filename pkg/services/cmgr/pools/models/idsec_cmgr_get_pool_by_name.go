package models

// IdsecCmgrGetPoolByName is a struct representing the filter for getting a specific pool by name in the Idsec CMGR service.
type IdsecCmgrGetPoolByName struct {
	Name string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the pool to get."`
}
