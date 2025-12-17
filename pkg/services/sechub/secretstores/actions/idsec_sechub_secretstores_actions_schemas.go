package actions

import storesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"

// ActionToSchemaMap is a map that defines the mapping between Sec Hub secrets stores action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"secret-store":             &storesmodels.IdsecSecHubGetSecretStore{},
	"list-secret-stores":       nil,
	"list-secret-stores-by":    &storesmodels.IdsecSecHubSecretStoresFilters{},
	"secret-store-conn-status": &storesmodels.IdsecSecHubGetSecretStoreConnectionStatus{},
	"set-secret-store-state":   &storesmodels.IdsecSecHubSetSecretStoreState{},
	"set-secret-stores-state":  &storesmodels.IdsecSecHubSetSecretStoresState{},
	"secret-stores-stats":      nil,
	"delete-secret-store":      &storesmodels.IdsecSecHubDeleteSecretStore{},
	"create-secret-store":      &storesmodels.IdsecSecHubCreateSecretStore{},
	"update-secret-store":      &storesmodels.IdsecSecHubUpdateSecretStore{},
}
