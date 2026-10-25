package secrets

import (
	"context"
	"fmt"
	"net/http"

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

// This method is intended for Terraform use only.
// FindByNameAndStoreId looks up a single secret by name and store ID.
// Returns an error if zero or more than one secret matches, or if the secret's onboarding status is NOT_CANDIDATE.
func (s *IdsecSecHubSecretsService) FindByNameAndStoreId(req *secretsmodels.IdsecSecHubFindSecretByNameAndStoreID) (*secretsmodels.IdsecSecHubSecret, error) {
	s.Logger.Info("Finding secret [%s] in store [%s]", req.Name, req.StoreID)

	items, err := s.fetchSecretCandidates(req.Name, req.StoreID)
	if err != nil {
		return nil, err
	}

	secret, err := s.resolveUniqueSecret(items, req.Name, req.StoreID)
	if err != nil {
		return nil, err
	}

	if secret.OnboardData.Status == string(secretsmodels.OnboardStatusNotCandidate) {
		return nil, fmt.Errorf("secret %q in store %q cannot be onboarded to PAM: %s", req.Name, req.StoreID, secret.OnboardData.Message)
	}
	return secret, nil
}

// fetchSecretCandidates queries the SecHub API for secrets matching the given name and store ID.
// The API only supports CONTAINS, not exact-match operators.
// limit=2 lets us distinguish "not found" / "unique" / "ambiguous" without fetching more results than needed.
func (s *IdsecSecHubSecretsService) fetchSecretCandidates(name, storeID string) ([]interface{}, error) {
	query := map[string]string{
		"filter": fmt.Sprintf(`name CONTAINS "%s" AND storeId CONTAINS "%s"`, name, storeID),
		"limit":  "2",
		"sort":   "name ASC",
	}
	response, err := s.ISPClient().Get(context.Background(), sechubURL, query)
	if err != nil {
		return nil, err
	}
	defer pagination.CloseResponse(response)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to find secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	resultJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	resultMap, ok := resultJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to find secret: unexpected response format")
	}
	return pagination.ExtractItemsFromResult(resultMap, "Secrets", "secrets")
}

// resolveUniqueSecret uses lexicographic ordering (name ASC) to determine whether the search
// produced an exact match. Because the API only supports CONTAINS, results are sorted by name
// so that the target name—if present—always lands at items[0].
//
//   - items[0] not an exact match → secret not found
//   - items[0] exact match, no items[1] → unique match, success
//   - items[0] exact match, items[1] also exact → duplicate secret, error
//   - items[0] exact match, items[1] is a lexicographic neighbour → unique match, success
func (s *IdsecSecHubSecretsService) resolveUniqueSecret(items []interface{}, name, storeID string) (*secretsmodels.IdsecSecHubSecret, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("secret %q not found in store %q — if the secret was recently created, it may not have been discovered by a Secrets Hub scan yet. Wait for the scan to complete and run terraform apply again", name, storeID)
	}
	var first secretsmodels.IdsecSecHubSecret
	if err := mapstructure.Decode(items[0], &first); err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}
	if first.Name != name || first.StoreID != storeID {
		return nil, fmt.Errorf("secret %q not found in store %q", name, storeID)
	}
	if len(items) > 1 {
		var second secretsmodels.IdsecSecHubSecret
		if err := mapstructure.Decode(items[1], &second); err != nil {
			return nil, fmt.Errorf("failed to decode secret: %w", err)
		}
		if second.Name == name && second.StoreID == storeID {
			return nil, fmt.Errorf("too many secrets matched name %q in store %q; use a more specific name", name, storeID)
		}
		// Second result is a lexicographic neighbour — not a duplicate
	}
	return &first, nil
}
