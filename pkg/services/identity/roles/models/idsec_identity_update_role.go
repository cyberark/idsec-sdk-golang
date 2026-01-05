package models

// IdsecIdentityUpdateRole represents the schema for updating a role.
type IdsecIdentityUpdateRole struct {
	RoleID      string   `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role id to update"`
	RoleName    string   `json:"role_name,omitempty" mapstructure:"role_name" flag:"role-name" desc:"Role name to update"`
	Description string   `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"New description of the role"`
	AdminRights []string `json:"admin_rights,omitempty" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights to set for the role"`
}
