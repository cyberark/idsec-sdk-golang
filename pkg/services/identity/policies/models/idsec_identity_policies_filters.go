package models

// IdsecIdentityPoliciesFilters represents the filters for listing identity policies.
type IdsecIdentityPoliciesFilters struct {
	PolicyNames  []string `json:"policy_names,omitempty" mapstructure:"policy_names" flag:"policy-names" desc:"Filter policies by names"`
	PolicyStatus string   `json:"policy_status,omitempty" mapstructure:"policy_status" flag:"policy-status" desc:"Filter policies by status" choices:"Active,Inactive"`
}
