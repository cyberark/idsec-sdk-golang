package models

// IdsecIdentityRoleAttributesSchemaColumn represents a role attribute schema column.
type IdsecIdentityRoleAttributesSchemaColumn struct {
	ID          string `json:"id,omitempty" mapstructure:"id" flag:"id" desc:"Unique identifier of the attribute column"`
	Name        string `json:"name" mapstructure:"name" flag:"name" desc:"Name of the attribute column"`
	Type        string `json:"type" mapstructure:"type" flag:"type" desc:"Data type of the attribute column (e.g., Text)"`
	Description string `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the attribute column"`
}

// IdsecIdentityRoleAttributesSchema represents the response containing role attribute schema columns.
type IdsecIdentityRoleAttributesSchema struct {
	Columns    []IdsecIdentityRoleAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of role attribute schema columns"`
	TotalCount int                                       `json:"total_count" mapstructure:"total_count" flag:"total-count" desc:"Total number of attribute schema columns"`
}
