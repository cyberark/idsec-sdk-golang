package models

// IdsecUAPGetPolicyByNameRequest represents the request to get a policy by its name.
type IdsecUAPGetPolicyByNameRequest struct {
	PolicyName string `json:"policy_name" mapstructure:"policy_name" flag:"policy-name" desc:"Policy name to be retrieved"`
}
