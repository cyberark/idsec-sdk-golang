package models

// IdsecIdentitySetPoliciesOrder represents the schema for setting the order of identity policies.
type IdsecIdentitySetPoliciesOrder struct {
	PoliciesOrder []string `json:"policies_order" mapstructure:"policies_order" flag:"policies-order" desc:"List of policy names in the desired order, where the first policy in the list will be the most prioritized one. policies which do not appear in the list will be ordered after the listed policies based on the existing order."`
}
