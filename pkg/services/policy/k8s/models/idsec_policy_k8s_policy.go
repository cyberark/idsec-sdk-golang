package models

import policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"

// IdsecPolicyK8sPolicy represents a K8s cluster access policy.
type IdsecPolicyK8sPolicy struct {
	policycommonmodels.IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	ConnectionMethod                                 string                                   `json:"connection_method,omitempty" mapstructure:"connection_method,omitempty" flag:"connection-method" desc:"The method used to connect to the cluster. A SIA connector for Kubernetes must be installed and configured, regardless of the connection method." choices:"direct,proxy"`
	Conditions                                       policycommonmodels.IdsecPolicyConditions `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The allowed session length, and the access window during which a session can be started."`
	Targets                                          IdsecPolicyK8sTargets                    `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"Kubernetes cluster targets"`
}
