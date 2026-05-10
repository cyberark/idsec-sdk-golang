package models

// IdsecIdentityGetPolicy represents the schema for retrieving an identity policy.
type IdsecIdentityGetPolicy struct {
	PolicyName           string `json:"policy_name,omitempty" mapstructure:"policy_name" flag:"policy-name" desc:"Policy Name to retrieve"`
	FilterSystemSettings bool   `json:"filter_system_settings,omitempty" mapstructure:"filter_system_settings" flag:"filter-system-settings" desc:"Indicates whether to filter system settings when returning the policy"`
}
