package models

// IdsecPCloudDeleteApplicationAuthMethod represents the model for deleting a pCloud application authentication method.
type IdsecPCloudDeleteApplicationAuthMethod struct {
	AppID  string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
	AuthID string `json:"auth_id" mapstructure:"auth_id" flag:"auth-id" desc:"The authentication method ID"`
}
