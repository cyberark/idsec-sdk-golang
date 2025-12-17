package actions

import policiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub sync policies action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create-sync-policy":    &policiesmodels.IdsecSechubCreateSyncPolicy{},
	"delete-sync-policy":    &policiesmodels.IdsecSecHubDeleteSyncPolicy{},
	"sync-policy":           &policiesmodels.IdsecSecHubGetSyncPolicy{},
	"list-sync-policies":    &policiesmodels.IdsecSecHubGetSyncPolicies{},
	"list-sync-policies-by": &policiesmodels.IdsecSecHubSyncPoliciesFilters{},
	"set-sync-policy-state": &policiesmodels.IdsecSecHubSetSyncPolicyState{},
	"sync-policies-stats":   nil,
}
