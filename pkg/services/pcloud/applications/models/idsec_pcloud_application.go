package models

// IdsecPCloudApplication represents the model for a pCloud application.
type IdsecPCloudApplication struct {
	AppID               string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
	Description         string `json:"description" mapstructure:"description" flag:"description" desc:"The application description"`
	Location            string `json:"location" mapstructure:"location" flag:"location" desc:"The application location"`
	AccessPermittedFrom int    `json:"access_permitted_from" mapstructure:"access_permitted_from" flag:"access-permitted-from" desc:"The timestamp from which access is permitted"`
	AccessPermittedTo   int    `json:"access_permitted_to" mapstructure:"access_permitted_to" flag:"access-permitted-to" desc:"The timestamp until which access is permitted"`
	ExpirationDate      string `json:"expiration_date" mapstructure:"expiration_date" flag:"expiration-date" desc:"The application expiration date"`
	Disabled            bool   `json:"disabled" mapstructure:"disabled" flag:"disabled" desc:"Whether the application is disabled or not"`
	BusinessOwnerFName  string `json:"business_owner_f_name" mapstructure:"business_owner_f_name" flag:"business-owner-f-name" desc:"The business owner's first name"`
	BusinessOwnerLName  string `json:"business_owner_l_name" mapstructure:"business_owner_l_name" flag:"business-owner-l-name" desc:"The business owner's last name"`
	BusinessOwnerEmail  string `json:"business_owner_email" mapstructure:"business_owner_email" flag:"business-owner-email" desc:"The business owner's email address"`
	BusinessOwnerPhone  string `json:"business_owner_phone" mapstructure:"business_owner_phone" flag:"business-owner-phone" desc:"The business owner's phone number"`
}
