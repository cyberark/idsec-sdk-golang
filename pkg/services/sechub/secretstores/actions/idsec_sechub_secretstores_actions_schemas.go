package actions

import storesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub secrets stores action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"get":         &storesmodels.IdsecSecHubGetSecretStore{},
	"list":        nil,
	"list-by":     &storesmodels.IdsecSecHubSecretStoresFilters{},
	"conn-status": &storesmodels.IdsecSecHubGetSecretStoreConnectionStatus{},
	"set-state":   &storesmodels.IdsecSecHubSetSecretStoreState{},
	"set-states":  &storesmodels.IdsecSecHubSetSecretStoresState{},
	"stats":       nil,
	"delete":      &storesmodels.IdsecSecHubDeleteSecretStore{},
	"create":      &storesmodels.IdsecSecHubCreateSecretStore{},
	"update":      &storesmodels.IdsecSecHubUpdateSecretStore{},
	"update-tf":   &storesmodels.IdsecSecHubUpdateTfSecretStore{},
}
