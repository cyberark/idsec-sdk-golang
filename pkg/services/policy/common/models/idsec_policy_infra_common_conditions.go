package models

// IdsecPolicyInfraCommonConditions represents common conditions for infra policies.
type IdsecPolicyInfraCommonConditions struct {
	IdsecPolicyConditions `mapstructure:",squash"`
	IdleTime              int `json:"idle_time,omitempty" mapstructure:"idle_time,omitempty" flag:"idle-time" desc:"The maximum idle time before the session ends, in minutes." validate:"gt=0,lte=120" default:"10"`
}
