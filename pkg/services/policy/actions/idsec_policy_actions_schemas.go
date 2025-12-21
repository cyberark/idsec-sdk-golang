package actions

import policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"

// ActionToSchemaMap defines the mapping of actions to schemas for the Policy service.
var ActionToSchemaMap = map[string]interface{}{
	"policies-stats":   nil,
	"list-policies":    nil,
	"list-policies-by": &policycommonmodels.IdsecPolicyFilters{},
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
