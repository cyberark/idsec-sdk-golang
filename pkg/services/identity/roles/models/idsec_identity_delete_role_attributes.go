package models

// IdsecIdentityDeleteRoleAttributes represents the request to delete role attributes.
type IdsecIdentityDeleteRoleAttributes struct {
	RoleID         string            `json:"role_id" mapstructure:"role_id" flag:"role-id" desc:"ID of the role whose attributes are to be deleted" validate:"required"`
	AttributeNames []string          `json:"attribute_names" mapstructure:"attribute_names" flag:"attribute-names" desc:"List of attribute names to delete, either this or 'attributes' must be provided"`
	Attributes     map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of attributes to delete, either this or 'attribute_names' must be provided"`
}
