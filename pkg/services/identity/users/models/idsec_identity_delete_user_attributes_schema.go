package models

// IdsecIdentityDeleteUserAttributesSchema represents the request to delete user attributes schema columns.
type IdsecIdentityDeleteUserAttributesSchema struct {
	ColumnNames []string                                  `json:"column_names" mapstructure:"column_names" flag:"column-names" desc:"List of attribute column names to delete, either this or 'columns' must be provided"`
	Columns     []IdsecIdentityUserAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of attribute columns to delete, either this or 'column_names' must be provided"`
}
