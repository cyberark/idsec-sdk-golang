package models

import policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"

// IdsecPolicyK8sPolicy represents a K8s cluster access policy.
type IdsecPolicyK8sPolicy struct {
	policycommonmodels.IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                       policycommonmodels.IdsecPolicyConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The allowed session length, and the access window during which a session can be started."`
	Targets                                          IdsecPolicyK8sTargets                    `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"K8s cluster targets"`
}
