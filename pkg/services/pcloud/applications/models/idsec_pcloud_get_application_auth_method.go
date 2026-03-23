package models

// IdsecPCloudGetApplicationAuthMethod represents the model for getting a pCloud application authentication method.
type IdsecPCloudGetApplicationAuthMethod struct {
	AppID  string `json:"app_id" mapstructure:"app_id" flag:"app-id" desc:"The application ID"`
	AuthID string `json:"auth_id" mapstructure:"auth_id" flag:"auth-id" desc:"The authentication method ID"`
}
