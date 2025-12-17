package models

// IdsecUAPGetPolicyRequest represents the request to get a policy by its ID.
type IdsecUAPGetPolicyRequest struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"Policy id to be retrieved"`
}
