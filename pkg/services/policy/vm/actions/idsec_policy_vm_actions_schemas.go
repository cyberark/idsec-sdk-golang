package actions

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the infrastructure VM service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &policyvmmodels.IdsecPolicyVMAccessPolicy{},
	"delete-policy":    &policycommonmodels.IdsecPolicyDeletePolicyRequest{},
	"update-policy":    &policyvmmodels.IdsecPolicyVMAccessPolicy{},
	"policy":           &policycommonmodels.IdsecPolicyGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &policyvmmodels.IdsecPolicyVMFilters{},
	"policies-stats":   nil,
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
