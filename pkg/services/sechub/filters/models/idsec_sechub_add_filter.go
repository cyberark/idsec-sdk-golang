package models

// IdsecSecHubCreateFilterData defines the data structure for adding a filter in the Secrets Hub.
type IdsecSecHubCreateFilterData struct {
	SafeName string `json:"safe_name" mapstructure:"safe_name" desc:"The Safe name as defined in PAM" flag:"safe-name" validate:"required"`
}

// IdsecSecHubCreateFilter defines the structure for adding a filter in the Secrets Hub.
type IdsecSecHubCreateFilter struct {
	StoreID string                      `json:"store_id" mapstructure:"store_id" desc:"Secrets Store Id for Secrets Hub" flag:"store-id" validate:"required"`
	Data    IdsecSecHubCreateFilterData `json:"data" mapstructure:"data" desc:"Data for the secret store"`
	Type    string                      `json:"type" mapstructure:"type" desc:"The secrets filter type (PAM_SAFE)" flag:"type" validate:"required" default:"PAM_SAFE" choices:"PAM_SAFE"`
}
