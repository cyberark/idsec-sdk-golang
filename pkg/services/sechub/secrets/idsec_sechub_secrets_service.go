package secrets

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	secretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secrets/models"
)

const (
	sechubURL = "/api/secrets"
)

// IdsecSecHubSecretsPage is a page of IdsecSecHubSecret items.
type IdsecSecHubSecretsPage = common.IdsecPage[secretsmodels.IdsecSecHubSecret]

// IdsecSecHubSecretsService is the service for interacting with Secrets Hub secrets
type IdsecSecHubSecretsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSecHubSecretsService creates a new instance of IdsecSecHubSecretsService.
func NewIdsecSecHubSecretsService(authenticators ...auth.IdsecAuth) (*IdsecSecHubSecretsService, error) {
	secretsService := &IdsecSecHubSecretsService{}
	var secretsServiceInterface services.IdsecService = secretsService
	baseService, err := services.NewIdsecBaseService(secretsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", secretsService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	// Required as endpoints are currently beta
	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"Accept": "application/x.secretshub.beta+json",
	})

	secretsService.IdsecBaseService = baseService
	secretsService.IdsecISPBaseService = ispBaseService
	return secretsService, nil
}

func (s *IdsecSecHubSecretsService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSecHubSecretsService) getSecretsWithFilters(
	projection string,
	filter string,
	limit int,
	offset int,
	sort string,
) (<-chan *IdsecSecHubSecretsPage, error) {
	query := map[string]string{}
	if projection != "" {
		query["projection"] = projection
	}
	if filter != "" {
		query["filter"] = filter
	}
	if limit != 0 {
		query["limit"] = fmt.Sprintf("%d", limit)
	}
	if offset != 0 {
		query["offset"] = fmt.Sprintf("%d", offset)
	}
	if sort != "" {
		query["sort"] = sort
	}
	return pagination.ListAllPaginated[secretsmodels.IdsecSecHubSecret](
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), sechubURL, query),
		pagination.ListPaginatedConfig[secretsmodels.IdsecSecHubSecret]{
			ResourceName: "Secrets",
			Decode: func(resultMap map[string]interface{}) ([]*secretsmodels.IdsecSecHubSecret, error) {
				items, err := pagination.ExtractItemsFromResult(resultMap, "Secrets", "secrets")
				if err != nil {
					return nil, err
				}
				var secrets []*secretsmodels.IdsecSecHubSecret
				if err := mapstructure.Decode(items, &secrets); err != nil {
					return nil, fmt.Errorf("failed to validate Secrets: %w", err)
				}
				return secrets, nil
			},
		},
	)
}

// Get returns a channel of IdsecSecHubSecretsPage containing all Secret Stores.
// https://api-docs.cyberark.com/docs/secretshub-api/kdyou8dae9r8m-get-secrets
func (s *IdsecSecHubSecretsService) Get() (<-chan *IdsecSecHubSecretsPage, error) {
	return s.getSecretsWithFilters(
		"",
		"",
		0,
		0,
		"",
	)
}

// ListBy returns a channel of IdsecSecHubSecretsPage containing secrets filtered by the given filters.
func (s *IdsecSecHubSecretsService) ListBy(secretsFilters *secretsmodels.IdsecSecHubSecretsFilter) (<-chan *IdsecSecHubSecretsPage, error) {
	return s.getSecretsWithFilters(
		secretsFilters.Projection,
		secretsFilters.Filter,
		secretsFilters.Limit,
		secretsFilters.Offset,
		secretsFilters.Sort,
	)
}

// Stats retrieves statistics about secrets.
func (s *IdsecSecHubSecretsService) Stats() (*secretsmodels.IdsecSecHubSecretsStats, error) {
	s.Logger.Info("Retrieving secret stats")
	secretsChan, err := s.Get()
	if err != nil {
		return nil, err
	}
	secrets := make([]*secretsmodels.IdsecSecHubSecret, 0)
	for page := range secretsChan {
		secrets = append(secrets, page.Items...)
	}
	var secretsStats secretsmodels.IdsecSecHubSecretsStats
	secretsStats.SecretsCount = len(secrets)
	secretsStats.SecretsCountByVendorType = make(map[string]int)
	secretsStats.SecretsCountByStoreName = make(map[string]int)
	secretsStats.SecretsCountSyncedByCyberArk = 0
	secretsStats.SecretsCountNotSyncedByCyberArk = 0
	for _, secret := range secrets {
		if _, ok := secretsStats.SecretsCountByVendorType[secret.VendorType]; !ok {
			secretsStats.SecretsCountByVendorType[secret.VendorType] = 0
		}
		if _, ok := secretsStats.SecretsCountByStoreName[secret.StoreName]; !ok {
			secretsStats.SecretsCountByStoreName[secret.StoreName] = 0
		}
		secretsStats.SecretsCountByVendorType[secret.VendorType]++
		secretsStats.SecretsCountByStoreName[secret.StoreName]++
		if secret.SyncedByCyberArk {
			secretsStats.SecretsCountSyncedByCyberArk++
		} else {
			secretsStats.SecretsCountNotSyncedByCyberArk++
		}
	}
	return &secretsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubSecretStoreService.
func (s *IdsecSecHubSecretsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
