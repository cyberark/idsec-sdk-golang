package models

// IdsecPCloudSafeMembersStats represents statistics about safe members.
type IdsecPCloudSafeMembersStats struct {
	SafeMembersCount          int            `json:"safe_members_count" mapstructure:"safe_members_count" desc:"Number of Safe members"`
	SafeMembersPermissionSets map[string]int `json:"safe_members_permission_sets" mapstructure:"safe_members_permission_sets" desc:"Number of members per permission set"`
	SafeMembersTypesCount     map[string]int `json:"safe_members_types_count" mapstructure:"safe_members_types_count" desc:"Number of members per type"`
}

// IdsecPCloudSafesMembersStats represents statistics about safe members per safe.
type IdsecPCloudSafesMembersStats struct {
	SafeMembersStats map[string]IdsecPCloudSafeMembersStats `json:"safe_members_stats" mapstructure:"safe_members_stats" desc:"Safe members statistics per safe"`
}
