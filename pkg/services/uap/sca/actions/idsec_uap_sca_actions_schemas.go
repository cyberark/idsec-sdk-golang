package actions

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapscamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sca/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the UAP SCA service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &uapscamodels.IdsecUAPSCACloudConsoleAccessPolicy{},
	"delete-policy":    &uapcommonmodels.IdsecUAPDeletePolicyRequest{},
	"update-policy":    &uapscamodels.IdsecUAPSCACloudConsoleAccessPolicy{},
	"policy":           &uapcommonmodels.IdsecUAPGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &uapscamodels.IdsecUAPSCAFilters{},
	"policies-stats":   nil,
	"policy-status":    &uapcommonmodels.IdsecUAPGetPolicyStatus{},
}
