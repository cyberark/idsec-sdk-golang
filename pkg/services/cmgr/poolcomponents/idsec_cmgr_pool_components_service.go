package poolcomponents

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
	componentsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolcomponents/models"
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
)

const (
	poolsComponentsURL = "api/pool-service/pools/components"
	poolComponentURL   = "api/pool-service/pools/%s/components/%s"
)

// IdsecCmgrPoolComponentPage is a page of IdsecCmgrPoolComponent items.
type IdsecCmgrPoolComponentPage = common.IdsecPage[componentsmodels.IdsecCmgrPoolComponent]

// IdsecCmgrPoolComponentsService is the service for managing CMGR pool components.
type IdsecCmgrPoolComponentsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCmgrPoolComponentsService creates a new instance of IdsecCmgrPoolComponentsService.
func NewIdsecCmgrPoolComponentsService(authenticators ...auth.IdsecAuth) (*IdsecCmgrPoolComponentsService, error) {
	componentsService := &IdsecCmgrPoolComponentsService{}
	var componentsServiceInterface services.IdsecService = componentsService
	baseService, err := services.NewIdsecBaseService(componentsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "connectormanagement", ".", "", componentsService.refreshAuth)
	if err != nil {
		return nil, err
	}

	componentsService.IdsecBaseService = baseService
	componentsService.IdsecISPBaseService = ispBaseService
	return componentsService, nil
}

func (s *IdsecCmgrPoolComponentsService) refreshAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func listWithCommonFilter[PageItemType any](
	logger *common.IdsecLogger,
	client *isp.IdsecISPServiceClient,
	name string, route string,
	commonFilter *poolsmodels.IdsecCmgrPoolsCommonFilter,
	idMappings map[string]string) (<-chan *common.IdsecPage[PageItemType], error) {
	logger.Info("Listing %s", name)
	pageChannel := make(chan *common.IdsecPage[PageItemType])
	go func() {
		defer close(pageChannel)
		filters := map[string]string{
			"projection": "EXTENDED",
		}
		if commonFilter != nil {
			if commonFilter.Filter != "" {
				filters["filter"] = commonFilter.Filter
			}
			if commonFilter.Order != "" {
				filters["order"] = commonFilter.Order
			}
			if commonFilter.PageSize != 0 {
				filters["pageSize"] = fmt.Sprintf("%d", commonFilter.PageSize)
			}
			if commonFilter.Sort != "" {
				filters["sort"] = commonFilter.Sort
			}
			if commonFilter.Projection != "" {
				filters["projection"] = commonFilter.Projection
			}
		}
		var contToken string
		for {
			if contToken != "" {
				filters["continuation_token"] = contToken
			}
			response, err := client.Get(context.Background(), route, filters)
			if err != nil {
				logger.Error("Failed to list %s: %v", name, err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				logger.Error("Failed to list %s - [%d] - [%s]", name, response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				logger.Error("Failed to decode response for %s: %v", name, err)
				return
			}
			resultMap := result.(map[string]interface{})
			if len(idMappings) >= 0 {
				for _, resourceItem := range resultMap["resources"].([]interface{}) {
					for key, value := range idMappings {
						if _, ok := resourceItem.(map[string]interface{})[key]; ok {
							resourceItem.(map[string]interface{})[value] = resourceItem.(map[string]interface{})[key]
						}
					}
				}
			}

			var items []*PageItemType
			err = mapstructure.Decode(resultMap["resources"], &items)
			if err != nil {
				logger.Error("Failed to decode resources for %s: %v", name, err)
				return
			}
			pageChannel <- &common.IdsecPage[PageItemType]{Items: items}
			pageInfo, ok := resultMap["page"].(map[string]interface{})
			if !ok || pageInfo["continuation_token"] == nil || pageInfo["continuation_token"] == "" {
				break
			}
			contToken = pageInfo["continuation_token"].(string)
			if totalResources, ok := pageInfo["total_resources_count"].(float64); ok {
				if pageSize, ok := pageInfo["page_size"].(float64); ok && totalResources == pageSize {
					break
				}
			}
		}
	}()
	return pageChannel, nil
}

// List lists all components in the connector management service.
func (s *IdsecCmgrPoolComponentsService) List() (<-chan *IdsecCmgrPoolComponentPage, error) {
	s.Logger.Info("Listing pools components")
	return listWithCommonFilter[componentsmodels.IdsecCmgrPoolComponent](
		s.Logger,
		s.ISPClient(),
		"pools components",
		poolsComponentsURL,
		nil,
		map[string]string{
			"id": "component_id",
		},
	)
}

// ListBy lists components by the specified filter in the connector management service.
func (s *IdsecCmgrPoolComponentsService) ListBy(componentsFilters *componentsmodels.IdsecCmgrPoolComponentsFilter) (<-chan *IdsecCmgrPoolComponentPage, error) {
	s.Logger.Info("Listing pools components by filter [%v]", componentsFilters)
	return listWithCommonFilter[componentsmodels.IdsecCmgrPoolComponent](
		s.Logger,
		s.ISPClient(),
		"pools components",
		poolsComponentsURL,
		&componentsFilters.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "component_id",
		},
	)
}

// Get retrieves a specific component by its ID from the connector management service.
func (s *IdsecCmgrPoolComponentsService) Get(getPoolComponent *componentsmodels.IdsecCmgrGetPoolComponent) (*componentsmodels.IdsecCmgrPoolComponent, error) {
	s.Logger.Info("Retrieving pool component [%s]", getPoolComponent.ComponentID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(poolComponentURL, getPoolComponent.PoolID, getPoolComponent.ComponentID), nil)
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
		return nil, fmt.Errorf("failed to retrieve pool component - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	poolComponentJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	poolComponentJSONMap := poolComponentJSON.(map[string]interface{})
	poolComponentJSONMap["component_id"] = poolComponentJSONMap["id"]
	var poolComponent componentsmodels.IdsecCmgrPoolComponent
	err = mapstructure.Decode(poolComponentJSONMap, &poolComponent)
	if err != nil {
		return nil, err
	}
	return &poolComponent, nil
}

// ServiceConfig returns the service configuration for the IdsecCmgrPoolComponentsService.
func (s *IdsecCmgrPoolComponentsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
