package models

// IdsecIdentityListRoleMembers represents the schema for listing members of a role.
type IdsecIdentityListRoleMembers struct {
	RoleName string `json:"role_name,omitempty" mapstructure:"role_name" flag:"role-name" desc:"Name of the role to get members of"`
	RoleID   string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"ID of the role to get members of"`
}
