package models

// IdsecPolicyInfraCommonAccessPolicy represents a common access policy for infrastructure.
type IdsecPolicyInfraCommonAccessPolicy struct {
	IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                    IdsecPolicyInfraCommonConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time, session, and idle time conditions of the policy"`
}
