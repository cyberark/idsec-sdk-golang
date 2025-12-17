package models

// IdsecSecHubAddFilterData defines the data structure for adding a filter in the Secrets Hub.
type IdsecSecHubAddFilterData struct {
	SafeName string `json:"safe_name" mapstructure:"safe_name" desc:"The Safe name as defined in PAM" flag:"safe-name" validate:"required"`
}

// IdsecSecHubAddFilter defines the structure for adding a filter in the Secrets Hub.
type IdsecSecHubAddFilter struct {
	StoreID string                   `json:"store_id" mapstructure:"store_id" desc:"Secrets Store Id for Secrets Hub" flag:"store-id" validate:"required"`
	Data    IdsecSecHubAddFilterData `json:"data" mapstructure:"data" desc:"Data for the secret store"`
	Type    string                   `json:"type" mapstructure:"type" desc:"The secrets filter type (PAM_SAFE)" flag:"type" validate:"required" default:"PAM_SAFE" choices:"PAM_SAFE"`
}
