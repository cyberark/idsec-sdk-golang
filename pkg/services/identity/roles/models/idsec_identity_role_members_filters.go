package models

// IdsecIdentityRoleMembersFilter represents the schema for filtering role members.
type IdsecIdentityRoleMembersFilter struct {
	RoleName    string   `json:"role_name,omitempty" mapstructure:"role_name" flag:"role-name" desc:"Filter by Role Name"`
	RoleID      string   `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Filter by Role ID"`
	MemberTypes []string `json:"member_types,omitempty" mapstructure:"member_types" flag:"member-types" desc:"Filter by Member Types (USER,GROUP,ROLE)" choices:"USER,GROUP,ROLE"`
}
