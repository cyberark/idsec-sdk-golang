package secrets

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
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
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
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
	client, err := isp.FromISPAuth(ispAuth, "secretshub", ".", "", secretsService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	// Required as endpoints are currently beta
	client.UpdateHeaders(map[string]string{
		"Accept": "application/x.secretshub.beta+json",
	})
	secretsService.client = client
	secretsService.ispAuth = ispAuth
	secretsService.IdsecBaseService = baseService
	return secretsService, nil
}

func (s *IdsecSecHubSecretsService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
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
	results := make(chan *IdsecSecHubSecretsPage)
	go func() {
		defer close(results)
		for {
			response, err := s.client.Get(context.Background(), sechubURL, query)
			if err != nil {
				s.Logger.Error("Failed to list Secrets %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list Secrets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}
			resultMap := result.(map[string]interface{})
			var secretsJSON []interface{}
			if secrets, ok := resultMap["secrets"]; ok {
				secretsJSON = secrets.([]interface{})
			} else {
				s.Logger.Error("Failed to list Secrets, unexpected result")
				return
			}
			for i, secrets := range secretsJSON {
				if secretsMap, ok := secrets.(map[string]interface{}); ok {
					if secretStoreID, ok := secretsMap["id"]; ok {
						secretsJSON[i].(map[string]interface{})["id"] = secretStoreID
					}
				}
			}
			var secrets []*secretsmodels.IdsecSecHubSecret
			if err := mapstructure.Decode(secretsJSON, &secrets); err != nil {
				s.Logger.Error("Failed to validate Secrets: %v", err)
				return
			}
			results <- &IdsecSecHubSecretsPage{Items: secrets}
			if nextLink, ok := resultMap["nextLink"].(string); ok {
				nextQuery, _ := url.Parse(nextLink)
				queryValues := nextQuery.Query()
				query = make(map[string]string)
				for key, values := range queryValues {
					if len(values) > 0 {
						query[key] = values[0]
					}
				}
			} else {
				break
			}
		}
	}()
	return results, nil
}

// Secrets returns a channel of IdsecSecHubSecretsPage containing all Secret Stores.
// https://api-docs.cyberark.com/docs/secretshub-api/kdyou8dae9r8m-get-secrets
func (s *IdsecSecHubSecretsService) Secrets() (<-chan *IdsecSecHubSecretsPage, error) {
	return s.getSecretsWithFilters(
		"",
		"",
		0,
		0,
		"",
	)
}

// ListSecretsBy returns a channel of IdsecSecHubSecretsPage containing secrets filtered by the given filters.
func (s *IdsecSecHubSecretsService) ListSecretsBy(secretsFilters *secretsmodels.IdsecSecHubSecretsFilter) (<-chan *IdsecSecHubSecretsPage, error) {
	return s.getSecretsWithFilters(
		secretsFilters.Projection,
		secretsFilters.Filter,
		secretsFilters.Limit,
		secretsFilters.Offset,
		secretsFilters.Sort,
	)
}

// SecretsStats retrieves statistics about secrets.
func (s *IdsecSecHubSecretsService) SecretsStats() (*secretsmodels.IdsecSecHubSecretsStats, error) {
	s.Logger.Info("Retrieving secret stats")
	secretsChan, err := s.Secrets()
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
