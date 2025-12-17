package actions

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
	uapsiadbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db/models"
)

// ActionToSchemaMap defines the mapping of actions to schemas for the UAP SIA DB service.
var ActionToSchemaMap = map[string]interface{}{
	"add-policy":       &uapsiadbmodels.IdsecUAPSIADBAccessPolicy{},
	"delete-policy":    &uapcommonmodels.IdsecUAPDeletePolicyRequest{},
	"update-policy":    &uapsiadbmodels.IdsecUAPSIADBAccessPolicy{},
	"policy":           &uapcommonmodels.IdsecUAPGetPolicyRequest{},
	"list-policies":    nil,
	"list-policies-by": &uapsiadbmodels.IdsecUAPSIADBFilters{},
	"policies-stats":   nil,
	"policy-status":    &uapcommonmodels.IdsecUAPGetPolicyStatus{},
}
