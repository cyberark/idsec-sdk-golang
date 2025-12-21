package models

// IdsecPolicyGetPolicyRequest represents the request to get a policy by its ID.
type IdsecPolicyGetPolicyRequest struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"Policy id to be retrieved"`
}
