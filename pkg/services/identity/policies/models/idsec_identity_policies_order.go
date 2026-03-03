package models

// IdsecIdentityPoliciesOrder represents the schema for setting the order of identity policies.
type IdsecIdentityPoliciesOrder struct {
	PoliciesOrder []string `json:"policies_order" mapstructure:"policies_order" flag:"policies-order" desc:"List of policy names in the current order."`
}
