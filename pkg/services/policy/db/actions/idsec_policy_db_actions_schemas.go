package actions

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policydbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the Infrastructure DB service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &policydbmodels.IdsecPolicyDBAccessPolicy{},
	"delete-policy":    &policycommonmodels.IdsecPolicyDeletePolicyRequest{},
	"update-policy":    &policydbmodels.IdsecPolicyDBAccessPolicy{},
	"policy":           &policycommonmodels.IdsecPolicyGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &policydbmodels.IdsecPolicyDBFilters{},
	"policies-stats":   nil,
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
