package models

// IdsecIdentityAddMemberToRole represents the schema for adding a member to a role.
type IdsecIdentityAddMemberToRole struct {
	RoleID     string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role ID to add the member to"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Member name to add to the role" required:"true"`
	MemberType string `json:"member_type" mapstructure:"member_type" flag:"member-type" desc:"Type of member to add" required:"true" choices:"USER,GROUP,ROLE"`
}
