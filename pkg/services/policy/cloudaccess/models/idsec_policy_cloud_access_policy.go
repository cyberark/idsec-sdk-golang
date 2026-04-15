package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessCloudConsoleAccessPolicy represents a Cloud Console access policy.
type IdsecPolicyCloudAccessCloudConsoleAccessPolicy struct {
	policycommonmodels.IdsecPolicyCommonAccessPolicy `mapstructure:",squash"`
	Conditions                                       policycommonmodels.IdsecPolicyConditions    `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"The allowed session length, and the access window (days and times) during which a session can be started."`
	Targets                                          IdsecPolicyCloudAccessCloudConsoleTarget    `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"Cloud Console targets (AWS, Azure, GCP)"`
	InvalidResources                                 IdsecPolicyCloudAccessCloudInvalidResources `json:"invalid_resources,omitempty" mapstructure:"invalid_resources,omitempty" flag:"invalid-resources" desc:"Indicates the invalid resources that lead to the Error status in the policy."`
}
