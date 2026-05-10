package models

// IdsecIdentityUpdateRoleAttributesSchema represents the request to update one or more role attribute schema columns.
//
// The underlying RoleAttributes/UpdateAttribute API only updates a single attribute per
// call, so the columns are applied sequentially.
type IdsecIdentityUpdateRoleAttributesSchema struct {
	Columns []IdsecIdentityRoleAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of attribute columns to update" validate:"required,min=1"`
}
