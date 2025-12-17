package actions

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsiavmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the UAP SIA VM service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{},
	"delete-policy":    &uapcommonmodels.IdsecUAPDeletePolicyRequest{},
	"update-policy":    &uapsiavmmodels.IdsecUAPSIAVMAccessPolicy{},
	"policy":           &uapcommonmodels.IdsecUAPGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &uapsiavmmodels.IdsecUAPSIAVMFilters{},
	"policies-stats":   nil,
	"policy-status":    &uapcommonmodels.IdsecUAPGetPolicyStatus{},
}
