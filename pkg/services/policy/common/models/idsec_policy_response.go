package models

// IdsecPolicyResponse represents a minimal response containing a policy ID.
type IdsecPolicyResponse struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"Policy id"`
}
