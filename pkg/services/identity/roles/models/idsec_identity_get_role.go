package models

// IdsecIdentityGetRole represents the schema for finding the ID of a role by its name.
type IdsecIdentityGetRole struct {
	RoleID   string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role ID found by name"`
	RoleName string `json:"role_name" mapstructure:"role_name" flag:"role-name" desc:"Role name to find the id for" required:"true"`
}
