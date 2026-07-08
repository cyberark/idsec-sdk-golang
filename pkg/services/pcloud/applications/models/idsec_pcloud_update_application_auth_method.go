package models

// IdsecPCloudUpdateApplicationAuthMethod represents the model for updating a pCloud application authentication method.
type IdsecPCloudUpdateApplicationAuthMethod struct {
	IdsecPCloudCreateApplicationAuthMethod `mapstructure:",squash"`
	AuthID                                 string `json:"auth_id" mapstructure:"auth_id" flag:"auth-id" desc:"The authentication method ID to update"`
}
