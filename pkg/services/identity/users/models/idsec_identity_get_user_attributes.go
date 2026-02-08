package models

// IdsecIdentityGetUserAttributes represents the response containing user attributes.
type IdsecIdentityGetUserAttributes struct {
	UserID string `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"ID of the user whose attributes are retrieved"`
}
