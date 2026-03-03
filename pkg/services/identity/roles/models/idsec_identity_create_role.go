package models

// IdsecIdentityCreateRole represents the schema for creating a role.
type IdsecIdentityCreateRole struct {
	RoleName          string   `json:"role_name" mapstructure:"role_name" flag:"role-name" desc:"Role name to create" required:"true"`
	Description       string   `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the role"`
	AdminRights       []string `json:"admin_rights" mapstructure:"admin_rights" flag:"admin-rights" desc:"Admin rights to add to the role"`
	RoleType          string   `json:"role_type,omitempty" mapstructure:"role_type" flag:"role-type" desc:"Type of the role to create, can be PrincipalList, Script, or Everybody" choices:"PrincipalList,Script,Everybody" default:"PrincipalList"`
	DynamicRoleScript string   `json:"dynamic_role_script,omitempty" mapstructure:"dynamic_role_script" flag:"dynamic-role-script" desc:"Script for dynamic role, required if RoleType is Script"`
}
