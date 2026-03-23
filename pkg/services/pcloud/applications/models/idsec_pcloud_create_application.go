package models

// IdsecPCloudCreateApplication represents the model for creating a pCloud application.
type IdsecPCloudCreateApplication struct {
	AppID               string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID" validate:"required"`
	Description         string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"The application description"`
	Location            string `json:"location" mapstructure:"location" flag:"location" desc:"The application location" default:"\\"`
	AccessPermittedFrom int    `json:"access_permitted_from" mapstructure:"access_permitted_from" flag:"access-permitted-from" desc:"The timestamp from which access is permitted" default:"0"`
	AccessPermittedTo   int    `json:"access_permitted_to" mapstructure:"access_permitted_to" flag:"access-permitted-to" desc:"The timestamp until which access is permitted" default:"24"`
	ExpirationDate      string `json:"expiration_date,omitempty" mapstructure:"expiration_date,omitempty" flag:"expiration-date" desc:"The application expiration date"`
	Disabled            bool   `json:"disabled" mapstructure:"disabled" flag:"disabled" desc:"Whether the application is disabled or not" default:"false"`
	BusinessOwnerFName  string `json:"business_owner_f_name,omitempty" mapstructure:"business_owner_f_name,omitempty" flag:"business-owner-f-name" desc:"The business owner's first name"`
	BusinessOwnerLName  string `json:"business_owner_l_name,omitempty" mapstructure:"business_owner_l_name,omitempty" flag:"business-owner-l-name" desc:"The business owner's last name"`
	BusinessOwnerEmail  string `json:"business_owner_email,omitempty" mapstructure:"business_owner_email,omitempty" flag:"business-owner-email" desc:"The business owner's email address"`
	BusinessOwnerPhone  string `json:"business_owner_phone,omitempty" mapstructure:"business_owner_phone,omitempty" flag:"business-owner-phone" desc:"The business owner's phone number"`
}
