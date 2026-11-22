package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyGroupAccessConditions wraps policy-level conditions for group access.
// It extends IdsecPolicyConditions with AccessApproval (dual control).
type IdsecPolicyGroupAccessConditions struct {
	policycommonmodels.IdsecPolicyConditions `mapstructure:",squash"`
	// AccessApproval is a pointer so that callers who never configure dual control never send
	// the field at all (Go's json.Marshal ignores "omitempty" on non-pointer structs, so a value
	// type here would always serialize "access_approval":{"required":false}). Leaving this pointer
	// unset keeps the request byte-identical to policies created before dual control existed.
	AccessApproval *policycommonmodels.IdsecPolicyAccessApprovalCondition `json:"access_approval,omitempty" mapstructure:"access_approval,omitempty" flag:"access-approval" desc:"For Google groups only. Determines whether additional approval is required before access to a target for an eligible identity can be elevated"`
}
