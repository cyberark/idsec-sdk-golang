package models

// IdsecIdentitySetPoliciesOrder represents the schema for setting the order of identity policies.
type IdsecIdentitySetPoliciesOrder struct {
	PoliciesOrder           []string `json:"policies_order" mapstructure:"policies_order" flag:"policies-order" desc:"List of policy names in the desired order, where the first policy in the list will be the most prioritized one. policies which do not appear in the list will be ordered after the listed policies based on the existing order."`
	ReturnAllPoliciesOrders bool     `json:"return_all_policies_orders" mapstructure:"return_all_policies_orders" flag:"return-all-policies-orders" desc:"Whether to return the order of all policies after the update, including those that were not included in the request. If false, only the order of the policies included in the request will be returned." default:"false"`
}
