package models

// IdsecIdentityDeleteRoleAttributesSchema represents the request to delete role attribute schema columns.
//
// Either AttributeIDs or ColumnNames must be supplied. Names are resolved to IDs via the
// current schema before being sent to the DeleteAttributes API.
type IdsecIdentityDeleteRoleAttributesSchema struct {
	IDs         []string                                  `json:"ids" mapstructure:"ids" flag:"ids" desc:"List of attribute IDs to delete; either this or 'column_names' must be provided"`
	ColumnNames []string                                  `json:"column_names" mapstructure:"column_names" flag:"column-names" desc:"List of attribute column names to delete; either this or 'attribute_ids' must be provided"`
	Columns     []IdsecIdentityRoleAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of attribute columns to create" validate:"required,min=1"`
}
