package models

// IdsecPCloudApplicationAuthMethodsFilter represents the filter model for pCloud application authentication methods.
type IdsecPCloudApplicationAuthMethodsFilter struct {
	AppID     string   `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
	AuthTypes []string `json:"auth_types" mapstructure:"auth_types" flag:"auth-types" desc:"Filter by authentication method types"`
}
