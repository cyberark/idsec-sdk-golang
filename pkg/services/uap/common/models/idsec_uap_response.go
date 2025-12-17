package models

// IdsecUAPResponse represents the response containing a policy ID.
type IdsecUAPResponse struct {
	PolicyID string `json:"policy_id" mapstructure:"policy_id" flag:"policy-id" desc:"Policy id"`
}
