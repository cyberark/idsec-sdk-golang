package models

// IdsecIdentityRolesStats represents the schema for identity roles statistics.
type IdsecIdentityRolesStats struct {
	RolesCount             int            `json:"roles_count" mapstructure:"roles_count" desc:"Total number of roles"`
	RoleMembersCountByType map[string]int `json:"role_members_count_by_type" mapstructure:"role_members_count_by_type" desc:"Number of role members by type (e.g., USER, GROUP)"`
}
