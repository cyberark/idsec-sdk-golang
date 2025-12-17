package models

// IdsecSIADBStoreDescriptor represents the descriptor of a store in the Idsec SIA DB.
type IdsecSIADBStoreDescriptor struct {
	StoreID   string `json:"store_id,omitempty" mapstructure:"store_id" desc:"ID of the store"`
	StoreType string `json:"store_type,omitempty" mapstructure:"store_type" desc:"Type of the store"`
}
