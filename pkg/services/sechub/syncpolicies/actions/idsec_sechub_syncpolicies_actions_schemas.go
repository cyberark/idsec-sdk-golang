package actions

import policiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub sync policies action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":    &policiesmodels.IdsecSechubCreateSyncPolicy{},
	"delete":    &policiesmodels.IdsecSecHubDeleteSyncPolicy{},
	"get":       &policiesmodels.IdsecSecHubGetSyncPolicy{},
	"list":      &policiesmodels.IdsecSecHubGetSyncPolicies{},
	"list-by":   &policiesmodels.IdsecSecHubSyncPoliciesFilters{},
	"set-state": &policiesmodels.IdsecSecHubSetSyncPolicyState{},
	"stats":     nil,
	"update":    &policiesmodels.IdsecSecHubUpdateSyncPolicy{},
}
