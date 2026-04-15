package actions

import (
	policiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/models"
)

// ActionToSchemaMap is a map that defines the mapping between Policies action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":         &policiesmodels.IdsecIdentityCreatePolicy{},
	"update":         &policiesmodels.IdsecIdentityUpdatePolicy{},
	"update-default": &policiesmodels.IdsecIdentityUpdateDefaultPolicy{},
	"delete":         &policiesmodels.IdsecIdentityDeletePolicy{},
	"get":            &policiesmodels.IdsecIdentityGetPolicy{},
	"list":           nil,
	"list-by":        &policiesmodels.IdsecIdentityPoliciesFilters{},
	"stats":          nil,
	"set-order":      &policiesmodels.IdsecIdentitySetPoliciesOrder{},
	"get-order":      &policiesmodels.IdsecIdentityGetPoliciesOrder{},
}
