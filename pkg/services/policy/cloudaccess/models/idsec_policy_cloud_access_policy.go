package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessCloudConsoleAccessPolicy represents a Cloud Access policy definition.
type IdsecPolicyCloudAccessCloudConsoleAccessPolicy struct {
	policycommonmodels.IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                       IdsecPolicyCloudAccessConditions            `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The time and session conditions of the policy"`
	Targets                                          IdsecPolicyCloudAccessCloudConsoleTarget    `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"The targeted cloud provider and workspace"`
	InvalidResources                                 IdsecPolicyCloudAccessCloudInvalidResources `json:"invalid_resources,omitempty" mapstructure:"invalid_resources,omitempty" flag:"invalid-resources" desc:"Resources that are not valid for the policy"`
}
