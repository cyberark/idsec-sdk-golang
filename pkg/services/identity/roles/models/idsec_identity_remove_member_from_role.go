package models

// IdsecIdentityRemoveMemberFromRole represents the schema for removing a member from a role.
type IdsecIdentityRemoveMemberFromRole struct {
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Member name to remove from the role" required:"true"`
	MemberType string `json:"member_type" mapstructure:"member_type" flag:"member-type" desc:"Type of member to remove" required:"true" choices:"USER,GROUP,ROLE"`
	RoleID     string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role ID to remove the member from" required:"true"`
}
