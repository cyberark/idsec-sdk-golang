package models

// IdsecPolicyDeletePolicyRequest represents a delete-policy request.
type IdsecPolicyDeletePolicyRequest struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"Policy id to be deleted"`
}
