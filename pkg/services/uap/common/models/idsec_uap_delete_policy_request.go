package models

// IdsecUAPDeletePolicyRequest represents the request to delete a policy in UAP.
type IdsecUAPDeletePolicyRequest struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"The ID of the policy to be deleted"`
}
