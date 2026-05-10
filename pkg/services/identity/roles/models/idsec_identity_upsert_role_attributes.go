package models

// IdsecIdentityUpsertRoleAttributes represents the request to upsert role attributes.
type IdsecIdentityUpsertRoleAttributes struct {
	RoleID     string            `json:"role_id" mapstructure:"role_id" flag:"role-id" desc:"ID of the role whose attributes are to be upserted" validate:"required"`
	Attributes map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of attributes to upsert" validate:"required,min=1"`
}
