package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessConditions wraps policy-level time conditions for Cloud Access.
// It extends IdsecPolicyConditions with AccessApproval, which is specific to Cloud Access policies.
type IdsecPolicyCloudAccessConditions struct {
	policycommonmodels.IdsecPolicyConditions `mapstructure:",squash"`
	AccessApproval                           policycommonmodels.IdsecPolicyAccessApprovalCondition `json:"access_approval,omitempty" mapstructure:"access_approval,omitempty" flag:"access-approval" desc:"Determines whether additional approval is required before access to a target for an eligible identity can be elevated"`
}
