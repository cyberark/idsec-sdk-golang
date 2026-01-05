package models

// IdsecIdentityGetRoleMembersStats represents the schema for getting members statistics of a role.
type IdsecIdentityGetRoleMembersStats struct {
	RoleID   string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role ID to get the member from" required:"true"`
	RoleName string `json:"role_name,omitempty" mapstructure:"role_name" flag:"role-name" desc:"Role name to get the member from" required:"true"`
}
