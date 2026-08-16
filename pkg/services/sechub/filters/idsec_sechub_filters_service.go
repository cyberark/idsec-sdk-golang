package filters

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	filtersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/filters/models"
)

const (
	sechubURL = "/api/secret-stores/%s/filters"
	filterURL = "/api/secret-stores/%s/filters/%s"
)

// IdsecSecHubFiltersPage is a page of IdsecSecHubFilter items.
type IdsecSecHubFiltersPage = common.IdsecPage[filtersmodels.IdsecSecHubFilter]

// IdsecSecHubFiltersService is the service for interacting with Secrets Hub filters
type IdsecSecHubFiltersService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSecHubFiltersService creates a new instance of IdsecSecHubFiltersService.
func NewIdsecSecHubFiltersService(authenticators ...auth.IdsecAuth) (*IdsecSecHubFiltersService, error) {
	filtersService := &IdsecSecHubFiltersService{}
	var filtersServiceInterface services.IdsecService = filtersService
	baseService, err := services.NewIdsecBaseService(filtersServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", filtersService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}

	filtersService.IdsecBaseService = baseService
	filtersService.IdsecISPBaseService = ispBaseService
	return filtersService, nil
}

func (s *IdsecSecHubFiltersService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves the filters info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/rqykgubx980ul-get-secrets-filter
func (s *IdsecSecHubFiltersService) Get(getFilters *filtersmodels.IdsecSecHubGetFilter) (*filtersmodels.IdsecSecHubFilter, error) {
	if getFilters.StoreID == "" {
		s.Logger.Info("Setting Secret Store ID to default")
		getFilters.StoreID = "default"
	}
	if getFilters.FilterID == "" {
		s.Logger.Info("Setting Secret Store Filter ID to default")
		getFilters.FilterID = "default"
	}
	s.Logger.Info("Getting filter")
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(filterURL, getFilters.StoreID, getFilters.FilterID), nil)
	if err != nil {
		s.Logger.Error("Failed to list filters: %v", err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		s.Logger.Error("Failed to list Secret Store Filters - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		return nil, err
	}
	filterJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		s.Logger.Error("Failed to decode response: %v", err)
		return nil, err
	}
	var filter filtersmodels.IdsecSecHubFilter
	err = mapstructure.Decode(filterJSON, &filter)
	if err != nil {
		return nil, err
	}
	return &filter, nil
}

func decodeFiltersFromResultMap(resultMap map[string]interface{}) ([]*filtersmodels.IdsecSecHubFilter, error) {
	items, err := pagination.ExtractItemsFromResult(resultMap, "Secret Store filters", "filters")
	if err != nil {
		return nil, err
	}
	var filters []*filtersmodels.IdsecSecHubFilter
	if err := mapstructure.Decode(items, &filters); err != nil {
		return nil, fmt.Errorf("failed to validate Secret Store filters: %w", err)
	}
	return filters, nil
}

// List retrieves the filters info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/punr36gz4tuqe-get-all-secrets-filters
//
// This endpoint is not OData-paginated: it returns every filter for the secret store in a
// single response, so NextQuery always stops after the first page.
func (s *IdsecSecHubFiltersService) List(getFilters *filtersmodels.IdsecSecHubGetFilters) (<-chan *IdsecSecHubFiltersPage, error) {
	if getFilters.StoreID == "" {
		s.Logger.Info("Setting Secret Store ID to default")
		getFilters.StoreID = "default"
	}
	s.Logger.Info("Getting filters")

	return pagination.ListAllPaginated[filtersmodels.IdsecSecHubFilter](
		context.Background(),
		pagination.HTTPGetFetch(s.ISPClient(), fmt.Sprintf(sechubURL, getFilters.StoreID), nil),
		pagination.ListPaginatedConfig[filtersmodels.IdsecSecHubFilter]{
			ResourceName: "Secret Store filters",
			Decode:       decodeFiltersFromResultMap,
			NextQuery: func(_ map[string]interface{}, _ map[string]string) (map[string]string, bool) {
				return nil, false
			},
		},
	)
}

// Create adds a new filter for a specific secret store id
// https://api-docs.cyberark.com/docs/secretshub-api/ifgbuo8tmt1en-create-secrets-filter
func (s *IdsecSecHubFiltersService) Create(filter *filtersmodels.IdsecSecHubCreateFilter) (*filtersmodels.IdsecSecHubFilter, error) {
	s.Logger.Info("Adding filter for secret store [%s]", filter.StoreID)
	bodyMap := map[string]interface{}{
		"type": filter.Type,
		"data": map[string]string{
			"safeName": filter.Data.SafeName,
		},
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(sechubURL, filter.StoreID), bodyMap)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to create filter - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	filterJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var filterResponse filtersmodels.IdsecSecHubFilter
	err = mapstructure.Decode(filterJSON, &filterResponse)
	if err != nil {
		return nil, err
	}
	return &filterResponse, nil
}

// Delete deletes a specified filter based on secret store id and filter id
// https://api-docs.cyberark.com/docs/secretshub-api/h8q9q5xtkxqgz-delete-secrets-filter
func (s *IdsecSecHubFiltersService) Delete(filter *filtersmodels.IdsecSecHubDeleteFilter) error {
	s.Logger.Info("Deleting secret store [%s] filter [%s]", filter.StoreID, filter.FilterID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(filterURL, filter.StoreID, filter.FilterID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete filter - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubFiltersService.
func (s *IdsecSecHubFiltersService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
