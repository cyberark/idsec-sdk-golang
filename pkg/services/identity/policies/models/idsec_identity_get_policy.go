package models

// IdsecIdentityGetPolicy represents the schema for retrieving an identity policy.
type IdsecIdentityGetPolicy struct {
	PolicyName string `json:"policy_name,omitempty" mapstructure:"policy_name" flag:"policy-name" desc:"Policy Name to retrieve"`
}
