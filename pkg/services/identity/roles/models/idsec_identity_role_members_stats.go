package models

// IdsecIdentityRoleMembersStats represents the schema for role members statistics.
type IdsecIdentityRoleMembersStats struct {
	MembersCount       int            `json:"members_count" mapstructure:"members_count" desc:"Total number of role members"`
	MembersCountByType map[string]int `json:"members_count_by_type" mapstructure:"members_count_by_type" desc:"Number of role members by type (e.g., USER, GROUP)"`
}
