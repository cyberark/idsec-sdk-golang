package models

// IdsecSecHubGetFilters holds the StoreId for the request.
type IdsecSecHubGetFilters struct {
	StoreID string `json:"store_id" mapstructure:"store_id" desc:"Secrets Store Id for Secrets Hub" flag:"store-id" validate:"required"`
}

// IdsecSecHubGetFilter holds the StoreId for the request.
// Get all the secrets filters related to a secret store source, by the secret store unique identifier.
type IdsecSecHubGetFilter struct {
	StoreID  string `json:"store_id" mapstructure:"store_id" desc:"Secrets Store Id for Secrets Hub" flag:"store-id" validate:"required"`
	FilterID string `json:"filter_id" mapstructure:"filter_id" desc:"Filter ID for Secrets Hub" flag:"filter-id" validate:"required"`
}

// IdsecSecHubFilterData represents the data field in the filter.
type IdsecSecHubFilterData struct {
	SafeName string `json:"safe_name" mapstructure:"safe_name" desc:"The Safe name as defined in PAM."`
}

// IdsecSecHubFilter represents a single filter used to retrieve secrets from Idsec Secrets Hub.
type IdsecSecHubFilter struct {
	ID        string                `json:"id" mapstructure:"id" desc:"The unique identifier of the secrets filter."`
	Type      string                `json:"type" mapstructure:"type" desc:"The type of the secrets filter." choices:"PAM_SAFE"`
	Data      IdsecSecHubFilterData `json:"data" mapstructure:"data" desc:"Information about the PAM Safe."`
	CreatedAt string                `json:"created_at" mapstructure:"created_at" desc:"The secrets filter creation date."`
	UpdatedAt string                `json:"updated_at" mapstructure:"updated_at" desc:"The secrets filter last update date."`
	CreatedBy string                `json:"created_by" mapstructure:"created_by" desc:"The user who created the secrets filter."`
	UpdatedBy string                `json:"updated_by" mapstructure:"updated_by" desc:"The user who last updated the secrets filter."`
}
