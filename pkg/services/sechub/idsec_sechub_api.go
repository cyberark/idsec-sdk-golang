package sechub

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/configuration"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/scans"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/serviceinfo"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/syncpolicies"
)

// IdsecSecHubAPI is a struct that provides access to the Idsec SecHub API as a wrapped set of services.
type IdsecSecHubAPI struct {
	configurationService *configuration.IdsecSecHubConfigurationService
	filtersService       *filters.IdsecSecHubFiltersService
	scansService         *scans.IdsecSecHubScansService
	serviceInfoService   *serviceinfo.IdsecSecHubServiceInfoService
	secretsService       *secrets.IdsecSecHubSecretsService
	secretStoresService  *secretstores.IdsecSecHubSecretStoresService
	syncPoliciesService  *syncpolicies.IdsecSecHubSyncPoliciesService
}

// NewIdsecSecHubAPI creates a new instance of IdsecSecHubAPI with the provided IdsecISPAuth.
func NewIdsecSecHubAPI(ispAuth *auth.IdsecISPAuth) (*IdsecSecHubAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	configurationService, err := configuration.NewIdsecSecHubConfigurationService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	filtersService, err := filters.NewIdsecSecHubFiltersService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	scansService, err := scans.NewIdsecSecHubScansService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	secretsService, err := secrets.NewIdsecSecHubSecretsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	secretStoresService, err := secretstores.NewIdsecSecHubSecretStoresService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	serviceInfoService, err := serviceinfo.NewIdsecSecHubServiceInfoService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	syncPoliciesService, err := syncpolicies.NewIdsecSecHubSyncPoliciesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecSecHubAPI{
		serviceInfoService:   serviceInfoService,
		configurationService: configurationService,
		filtersService:       filtersService,
		scansService:         scansService,
		secretStoresService:  secretStoresService,
		secretsService:       secretsService,
		syncPoliciesService:  syncPoliciesService,
	}, nil
}

// Configuration returns the configuration service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) Configuration() *configuration.IdsecSecHubConfigurationService {
	return api.configurationService
}

// Filters returns the filters service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) Filters() *filters.IdsecSecHubFiltersService {
	return api.filtersService
}

// Scans returns the scans service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) Scans() *scans.IdsecSecHubScansService {
	return api.scansService
}

// Secrets returns the Secrets service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) Secrets() *secrets.IdsecSecHubSecretsService {
	return api.secretsService
}

// SecretStores returns the secret stores service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) SecretStores() *secretstores.IdsecSecHubSecretStoresService {
	return api.secretStoresService
}

// ServiceInfo returns the service info service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) ServiceInfo() *serviceinfo.IdsecSecHubServiceInfoService {
	return api.serviceInfoService
}

// SyncPolicies returns the sync policies service of the IdsecSecHubAPI instance.
func (api *IdsecSecHubAPI) SyncPolicies() *syncpolicies.IdsecSecHubSyncPoliciesService {
	return api.syncPoliciesService
}
