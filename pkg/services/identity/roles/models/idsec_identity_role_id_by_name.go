package models

// IdsecIdentityRoleIDByName represents the schema for finding the ID of a role by its name.
type IdsecIdentityRoleIDByName struct {
	RoleName string `json:"role_name" mapstructure:"role_name" flag:"role-name" desc:"Role name to find the id for" required:"true"`
}
