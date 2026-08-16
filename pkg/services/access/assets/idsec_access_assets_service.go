package assets

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	assetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/models"
)

const (
	assetsURL      = "/api/assets"
	assetSecretURL = "/api/assets/%s/secret"
)

// IdsecAccessAssetsService is the service for interacting with access assets.
type IdsecAccessAssetsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecAccessAssetsService creates a new instance of IdsecAccessAssetsService.
func NewIdsecAccessAssetsService(authenticators ...auth.IdsecAuth) (*IdsecAccessAssetsService, error) {
	assetsService := &IdsecAccessAssetsService{}
	var assetsServiceInterface services.IdsecService = assetsService
	baseService, err := services.NewIdsecBaseService(assetsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "userportal", "-", "", assetsService.refreshAccessAuth)
	if err != nil {
		return nil, err
	}

	assetsService.IdsecBaseService = baseService
	assetsService.IdsecISPBaseService = ispBaseService
	return assetsService, nil
}

func (s *IdsecAccessAssetsService) refreshAccessAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// buildListQuery converts a list assets request to query parameters.
func buildListQuery(listAssets *assetsmodels.IdsecAccessAssetsListAssetsRequest) map[string]string {
	query := map[string]string{}
	if listAssets == nil {
		return query
	}
	if listAssets.RecentsOnly {
		query["recents_only"] = "true"
	}
	if listAssets.FavoritesOnly {
		query["favorites_only"] = "true"
	}
	if listAssets.AccessMethod != "" {
		query["access_method"] = listAssets.AccessMethod
	}
	if listAssets.Limit != 0 {
		query["limit"] = fmt.Sprintf("%d", listAssets.Limit)
	}
	if listAssets.Sort != "" {
		query["sort"] = listAssets.Sort
	}
	if listAssets.Search != "" {
		query["search"] = listAssets.Search
	}
	return query
}

// List retrieves all access assets without any filters.
func (s *IdsecAccessAssetsService) List() ([]*assetsmodels.IdsecAccessAssetsAsset, error) {
	return s.ListBy(nil)
}

// ListBy retrieves access assets filtered by the provided request parameters.
func (s *IdsecAccessAssetsService) ListBy(listAssets *assetsmodels.IdsecAccessAssetsListAssetsRequest) ([]*assetsmodels.IdsecAccessAssetsAsset, error) {
	query := buildListQuery(listAssets)
	response, err := s.ISPClient().Get(context.Background(), assetsURL, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list assets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	result, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode assets response: %w", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to list assets, unexpected result type")
	}
	assetsJSON, ok := resultMap["assets"]
	if !ok {
		return nil, fmt.Errorf("failed to list assets, missing assets field")
	}
	assetsList, ok := assetsJSON.([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to list assets, unexpected assets type")
	}
	var assets []*assetsmodels.IdsecAccessAssetsAsset
	if err := mapstructure.Decode(assetsList, &assets); err != nil {
		return nil, fmt.Errorf("failed to decode assets: %w", err)
	}
	return assets, nil
}

// Secret retrieves the secret for a specific asset.
func (s *IdsecAccessAssetsService) Secret(secretRequest *assetsmodels.IdsecAccessAssetsSecretRequest) (*assetsmodels.IdsecAccessAssetsSecretResponse, error) {
	if secretRequest == nil {
		return nil, fmt.Errorf("secret request must not be nil")
	}
	s.Logger.Info("Retrieving secret for asset [%s]", secretRequest.AssetID)
	body := map[string]interface{}{}
	if secretRequest.Reason != "" {
		body["reason"] = secretRequest.Reason
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(assetSecretURL, secretRequest.AssetID), body)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get asset secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secretResponse assetsmodels.IdsecAccessAssetsSecretResponse
	err = mapstructure.Decode(secretJSON, &secretResponse)
	if err != nil {
		return nil, err
	}
	return &secretResponse, nil
}

// ServiceConfig returns the service configuration for the IdsecAccessAssetsService.
func (s *IdsecAccessAssetsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
