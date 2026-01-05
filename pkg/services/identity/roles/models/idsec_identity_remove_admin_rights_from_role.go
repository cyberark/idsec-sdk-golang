package models

// IdsecIdentityRemoveAdminRightsToRole represents the schema for removing admin rights from a role.
type IdsecIdentityRemoveAdminRightsToRole struct {
	RoleID      string   `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role id to remove admin rights from"`
	RoleName    string   `json:"role_name,omitempty" mapstructure:"role_name" flag:"role-name" desc:"Role name to remove admin rights from"`
	AdminRights []string `json:"admin_rights" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights to remove from the role" required:"true"`
}
