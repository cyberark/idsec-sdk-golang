package models

// IdsecIdentityUpsertUserAttributesSchema represents the request to upsert user attribute schema columns.
type IdsecIdentityUpsertUserAttributesSchema struct {
	Columns []IdsecIdentityUserAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of attribute columns to upsert" validate:"required,min=1"`
}
