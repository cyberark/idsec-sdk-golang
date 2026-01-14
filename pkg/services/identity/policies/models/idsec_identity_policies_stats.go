package models

// IdsecIdentityPoliciesStats represents statistics related to identity policies.
type IdsecIdentityPoliciesStats struct {
	PoliciesCount         int            `json:"policies_count" mapstructure:"policies_count" desc:"Total number of policies"`
	PoliciesCountByStatus map[string]int `json:"policies_count_by_status" mapstructure:"policies_count_by_status" desc:"Number of policies grouped by status"`
}
