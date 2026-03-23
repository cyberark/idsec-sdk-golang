package models

// IdsecPCloudListApplicationAuthMethods represents the model for listing pCloud application authentication methods.
type IdsecPCloudListApplicationAuthMethods struct {
	AppID string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
}
