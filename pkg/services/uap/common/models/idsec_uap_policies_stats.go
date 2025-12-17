package models

// IdsecUAPPoliciesStats represents statistics about policies.
type IdsecUAPPoliciesStats struct {
	PoliciesCount            int            `json:"policies_count" mapstructure:"policies_count" flag:"policies-count" desc:"Overall count of policies"`
	PoliciesCountPerStatus   map[string]int `json:"policies_count_per_status" mapstructure:"policies_count_per_status" flag:"policies-count-per-status" desc:"Policies count per status"`
	PoliciesCountPerProvider map[string]int `json:"policies_count_per_provider" mapstructure:"policies_count_per_provider" flag:"policies-count-per-provider" desc:"Policies count per target category"`
}
