package actions

import (
	policiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/models"
)

// ActionToSchemaMap is a map that defines the mapping between Policies action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create-policy":    &policiesmodels.IdsecIdentityCreatePolicy{},
	"update-policy":    &policiesmodels.IdsecIdentityUpdatePolicy{},
	"delete-policy":    &policiesmodels.IdsecIdentityDeletePolicy{},
	"policy":           &policiesmodels.IdsecIdentityGetPolicy{},
	"list-policies":    nil,
	"list-policies-by": &policiesmodels.IdsecIdentityPoliciesFilters{},
	"policies-stats":   nil,
}
