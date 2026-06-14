package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessConditions wraps policy-level time conditions for Cloud Access.
// It extends IdsecPolicyConditions with AccessApproval, which is specific to Cloud Access policies.
type IdsecPolicyCloudAccessConditions struct {
	policycommonmodels.IdsecPolicyConditions `mapstructure:",squash"`
	AccessWindow                             policycommonmodels.IdsecPolicyTimeCondition           `json:"access_window" mapstructure:"access_window" flag:"policy-cloud-access-window" desc:"The days and times when the user can connect to their target using this policy. Important: When the accessApproval.required property is set to true, omit this field entirely from the payload."`
	AccessApproval                           policycommonmodels.IdsecPolicyAccessApprovalCondition `json:"access_approval" mapstructure:"access_approval" flag:"access-approval" desc:"Determines whether additional approval is required before access to a target for an eligible identity can be elevated"`
}
