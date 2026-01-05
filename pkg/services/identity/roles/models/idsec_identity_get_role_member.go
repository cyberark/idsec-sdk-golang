package models

// IdsecIdentityGetRoleMember represents the schema for getting a member of a role.
type IdsecIdentityGetRoleMember struct {
	RoleID     string `json:"role_id,omitempty" mapstructure:"role_id" flag:"role-id" desc:"Role ID to get the member from" required:"true"`
	MemberID   string `json:"member_id,omitempty" mapstructure:"member_id" flag:"member-id" desc:"Member ID to get from the role"`
	MemberName string `json:"member_name,omitempty" mapstructure:"member_name" flag:"member-name" desc:"Member name to get from the role"`
}
