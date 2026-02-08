package models

// IdsecIdentityUpsertUserAttributes represents the request to upsert user attributes.
type IdsecIdentityUpsertUserAttributes struct {
	UserID     string            `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"ID of the user whose attributes are to be upserted" validate:"required"`
	Attributes map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of attributes to upsert" validate:"required,min=1"`
}
