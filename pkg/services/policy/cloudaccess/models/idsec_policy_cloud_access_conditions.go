package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessConditions wraps policy-level time conditions for Cloud Access.
// It currently mirrors IdsecPolicyConditions but exists for future Cloud Access extensions.
type IdsecPolicyCloudAccessConditions struct {
	policycommonmodels.IdsecPolicyConditions `mapstructure:",squash"`
}
