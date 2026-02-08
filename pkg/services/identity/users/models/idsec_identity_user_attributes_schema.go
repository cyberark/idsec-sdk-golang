package models

// IdsecIdentityUserAttributesSchemaColumn represents a user attribute schema column.
type IdsecIdentityUserAttributesSchemaColumn struct {
	Name         string `json:"name" mapstructure:"name" flag:"name" desc:"Internal name of the attribute column (e.g., CustomAtt_1)" validate:"required"`
	Title        string `json:"title" mapstructure:"title" flag:"title" desc:"Display title of the attribute column"`
	Type         string `json:"type" mapstructure:"type" flag:"type" desc:"Data type of the attribute column (e.g., Text, Int, Bool)" validate:"required"`
	Description  string `json:"description" mapstructure:"description" flag:"description" desc:"Description of the attribute column"`
	UserEditable bool   `json:"user_editable" mapstructure:"user_editable" flag:"user-editable" desc:"Indicates if the attribute column is editable by the user"`
}

// IdsecIdentityUserAttributesSchema represents the response containing user attribute schema columns.
type IdsecIdentityUserAttributesSchema struct {
	Columns    []IdsecIdentityUserAttributesSchemaColumn `json:"columns" mapstructure:"columns" flag:"columns" desc:"List of user attribute schema columns"`
	TotalCount int                                       `json:"total_count" mapstructure:"total_count" flag:"total-count" desc:"Total number of attribute schema columns"`
}
