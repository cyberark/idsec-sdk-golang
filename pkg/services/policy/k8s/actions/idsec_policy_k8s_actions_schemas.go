package actions

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyk8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the K8s cluster policy service.
var ActionToSchemaMap = map[string]interface{}{
	"create-policy":    &policyk8smodels.IdsecPolicyK8sPolicy{},
	"delete-policy":    &policycommonmodels.IdsecPolicyDeletePolicyRequest{},
	"update-policy":    &policyk8smodels.IdsecPolicyK8sPolicy{},
	"policy":           &policycommonmodels.IdsecPolicyGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &policyk8smodels.IdsecPolicyK8sFilters{},
	"policies-stats":   nil,
	"policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
	// Terraform-specific actions: wrappers that return flat structs (not channels/strings) so the
	// generic data source Read flow can map the result to state.
	"tf-list-policies-by": &policyk8smodels.IdsecPolicyK8sFilters{},
	"tf-policy-status":    &policycommonmodels.IdsecPolicyGetPolicyStatus{},
}
