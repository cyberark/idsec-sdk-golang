package models

// IdsecIdentityRoleAttributes represents the attribute values associated with a role.
type IdsecIdentityRoleAttributes struct {
	RoleID     string            `json:"role_id" mapstructure:"role_id" flag:"role-id" desc:"ID of the role"`
	Attributes map[string]string `json:"attributes" mapstructure:"attributes" flag:"attributes" desc:"Key-value pairs of role attributes"`
}
