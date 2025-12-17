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
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
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
	client, err := isp.FromISPAuth(ispAuth, "secretshub", ".", "", filtersService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}
	filtersService.client = client
	filtersService.ispAuth = ispAuth
	filtersService.IdsecBaseService = baseService
	return filtersService, nil
}

func (s *IdsecSecHubFiltersService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// Filter retrieves the filters info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/rqykgubx980ul-get-secrets-filter
func (s *IdsecSecHubFiltersService) Filter(getFilters *filtersmodels.IdsecSecHubGetFilter) (*filtersmodels.IdsecSecHubFilter, error) {
	if getFilters.StoreID == "" {
		s.Logger.Info("Setting Secret Store ID to default")
		getFilters.StoreID = "default"
	}
	if getFilters.FilterID == "" {
		s.Logger.Info("Setting Secret Store Filter ID to default")
		getFilters.FilterID = "default"
	}
	s.Logger.Info("Getting filter")
	response, err := s.client.Get(context.Background(), fmt.Sprintf(filterURL, getFilters.StoreID, getFilters.FilterID), nil)
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

// ListFilters retrieves the filters info from the Secrets Hub service.
// https://api-docs.cyberark.com/docs/secretshub-api/punr36gz4tuqe-get-all-secrets-filters
func (s *IdsecSecHubFiltersService) ListFilters(getFilters *filtersmodels.IdsecSecHubGetFilters) (<-chan *IdsecSecHubFiltersPage, error) {
	if getFilters.StoreID == "" {
		s.Logger.Info("Setting Secret Store ID to default")
		getFilters.StoreID = "default"
	}
	s.Logger.Info("Getting filters")

	results := make(chan *IdsecSecHubFiltersPage)
	go func() {
		defer close(results)
		response, err := s.client.Get(context.Background(), fmt.Sprintf(sechubURL, getFilters.StoreID), nil)
		if err != nil {
			s.Logger.Error("Failed to list filters: %v", err)
			return
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				common.GlobalLogger.Warning("Error closing response body")
			}
		}(response.Body)
		if response.StatusCode != http.StatusOK {
			s.Logger.Error("Failed to list Secret Store Filters - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
			return
		}
		result, err := common.DeserializeJSONSnake(response.Body)
		if err != nil {
			s.Logger.Error("Failed to decode response: %v", err)
			return
		}
		resultMap := result.(map[string]interface{})
		var filtersJSON []interface{}
		if filters, ok := resultMap["filters"]; ok {
			filtersJSON = filters.([]interface{})
		} else {
			s.Logger.Error("Failed to list Secret Store filters, unexpected result")
			return
		}
		for i, filtersMember := range filtersJSON {
			if filtersMemberMap, ok := filtersMember.(map[string]interface{}); ok {
				if ID, ok := filtersMemberMap["id"]; ok {
					filtersJSON[i].(map[string]interface{})["id"] = ID
				}
			}
		}
		var filters []*filtersmodels.IdsecSecHubFilter
		if err := mapstructure.Decode(filtersJSON, &filters); err != nil {
			s.Logger.Error("Failed to validate Secret Store filters: %v", err)
			return
		}

		results <- &IdsecSecHubFiltersPage{Items: filters}
	}()
	return results, nil
}

// AddFilter adds a new filter for a specific secret store id
// https://api-docs.cyberark.com/docs/secretshub-api/ifgbuo8tmt1en-create-secrets-filter
func (s *IdsecSecHubFiltersService) AddFilter(filter *filtersmodels.IdsecSecHubAddFilter) (*filtersmodels.IdsecSecHubFilter, error) {
	s.Logger.Info("Adding filter for secret store [%s]", filter.StoreID)
	bodyMap := map[string]interface{}{
		"type": filter.Type,
		"data": map[string]string{
			"safeName": filter.Data.SafeName,
		},
	}
	response, err := s.client.Post(context.Background(), fmt.Sprintf(sechubURL, filter.StoreID), bodyMap)
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

// DeleteFilter deletes a specified filter based on secret store id and filter id
// https://api-docs.cyberark.com/docs/secretshub-api/h8q9q5xtkxqgz-delete-secrets-filter
func (s *IdsecSecHubFiltersService) DeleteFilter(filter *filtersmodels.IdsecSecHubDeleteFilter) error {
	s.Logger.Info("Deleting secret store [%s] filter [%s]", filter.StoreID, filter.FilterID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(filterURL, filter.StoreID, filter.FilterID), nil, nil)
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
