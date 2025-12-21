package actions

import (
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the Cloud Access policy service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{},
	"delete-policy":    &policycommonmodels.IdsecPolicyDeletePolicyRequest{},
	"update-policy":    &cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{},
	"policy":           &policycommonmodels.IdsecPolicyGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &cloudaccessmodels.IdsecPolicyCloudAccessFilters{},
	"policies-stats":   nil,
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
