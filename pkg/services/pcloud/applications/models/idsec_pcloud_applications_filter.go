package models

// IdsecPCloudApplicationsFilter represents the filter model for pCloud applications.
type IdsecPCloudApplicationsFilter struct {
	Location           string `json:"location" mapstructure:"location" flag:"location" desc:"Filter by application location"`
	OnlyEnabled        *bool  `json:"only_enabled" mapstructure:"only_enabled" flag:"only-enabled" desc:"Whether to return only enabled applications"`
	BusinessOwnerName  string `json:"business_owner_name" mapstructure:"business_owner_name" flag:"business-owner-name" desc:"Filter by business owner name"`
	BusinessOwnerEmail string `json:"business_owner_email" mapstructure:"business_owner_email" flag:"business-owner-email" desc:"Filter by business owner email"`
}
