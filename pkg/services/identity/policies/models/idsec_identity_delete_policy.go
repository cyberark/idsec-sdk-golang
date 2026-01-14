package models

// IdsecIdentityDeletePolicy represents the schema for deleting an identity policy.
type IdsecIdentityDeletePolicy struct {
	PolicyName string `json:"policy_name,omitempty" mapstructure:"policy_name" flag:"policy-name" desc:"Policy name to delete"`
}
