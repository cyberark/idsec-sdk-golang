package models

// IdsecIdentityGetRoleByName represents the details required to get a role by its name.
type IdsecIdentityGetRoleByName struct {
	RoleName string `json:"role_name" mapstructure:"role_name" flag:"role-name" desc:"The name of the role to retrieve" validate:"required"`
}
