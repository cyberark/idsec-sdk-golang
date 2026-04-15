package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyGroupAccessPolicy represents an Entra group assignment policy (groupaccess).
type IdsecPolicyGroupAccessPolicy struct {
	policycommonmodels.IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                       policycommonmodels.IdsecPolicyConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time and session conditions of the policy"`
	Targets                                          IdsecPolicyGroupAccessTarget             `json:"targets" mapstructure:"targets" flag:"targets" desc:"Wrapper containing list of Entra group targets - mandatory."`
	InvalidResources                                 IdsecPolicyGroupAccessInvalidResources   `json:"invalid_resources,omitempty" mapstructure:"invalid_resources,omitempty" flag:"invalid-resources" desc:"Invalid group resources encountered while evaluating the policy"`
}
