package models

// IdsecIdentityCreateRoleAttributesSchema represents the request to create role attribute schema columns.
type IdsecIdentityCreateRoleAttributesSchema struct {
	Columns []IdsecIdentityRoleAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of attribute columns to create" validate:"required,min=1"`
}
