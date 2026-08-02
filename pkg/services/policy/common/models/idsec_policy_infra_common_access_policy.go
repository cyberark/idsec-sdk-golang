package models

// IdsecPolicyInfraCommonAccessPolicy represents a common access policy for infrastructure.
type IdsecPolicyInfraCommonAccessPolicy struct {
	IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                    IdsecPolicyInfraCommonConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time, session, idle time, and dual control conditions of the policy"`
}
