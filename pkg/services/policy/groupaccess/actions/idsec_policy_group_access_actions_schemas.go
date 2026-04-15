package actions

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the Group Access policy service.
var ActionToSchemaMap = map[string]interface{}{
	"create-policy":    &groupaccessmodels.IdsecPolicyGroupAccessPolicy{},
	"delete-policy":    &policycommonmodels.IdsecPolicyDeletePolicyRequest{},
	"update-policy":    &groupaccessmodels.IdsecPolicyGroupAccessPolicy{},
	"policy":           &policycommonmodels.IdsecPolicyGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &groupaccessmodels.IdsecPolicyGroupAccessFilters{},
	"policies-stats":   nil,
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
