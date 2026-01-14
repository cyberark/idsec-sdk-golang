package models

// IdsecIdentityRoleAdminRights represents the schema for a role admin right.
type IdsecIdentityRoleAdminRights struct {
	RoleID      string   `json:"role_id" mapstructure:"role_id" flag:"role-id" desc:"Identifier of the role" required:"true"`
	RoleName    string   `json:"role_name" mapstructure:"role_name" flag:"role-name" desc:"Name of the role" required:"true"`
	AdminRights []string `json:"admin_rights" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights assigned to the role"`
}
