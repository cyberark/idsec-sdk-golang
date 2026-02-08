package models

// IdsecIdentityDeleteUserAttributes represents the request to delete user attributes.
type IdsecIdentityDeleteUserAttributes struct {
	UserID         string            `json:"user_id" mapstructure:"user_id" flag:"user-id" desc:"ID of the user whose attributes are to be deleted" validate:"required"`
	AttributeNames []string          `json:"attribute_names" mapstructure:"attribute_names" flag:"attribute-names" desc:"List of attribute names to delete, either this or 'attributes' must be provided"`
	Attributes     map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of attributes to delete, either this or 'attribute_names' must be provided"`
}
