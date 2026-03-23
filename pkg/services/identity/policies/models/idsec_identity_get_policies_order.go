package models

// IdsecIdentityGetPoliciesOrder represents the schema for getting the order of identity policies.
type IdsecIdentityGetPoliciesOrder struct {
	PoliciesOrder []string `json:"policies_order" mapstructure:"policies_order" flag:"policies-order" desc:"List of policy names to get the order for, if not given, the order of all policies will be returned."`
}
