package networks

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
	networksmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks/models"
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
)

const (
	networksURL = "api/pool-service/networks"
	networkURL  = "api/pool-service/networks/%s"
)

// IdsecCmgrNetworkPage is a page of IdsecCmgrNetwork items.
type IdsecCmgrNetworkPage = common.IdsecPage[networksmodels.IdsecCmgrNetwork]

// IdsecCmgrNetworksService is the service for managing CMGR networks.
type IdsecCmgrNetworksService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCmgrNetworksService creates a new instance of IdsecCmgrNetworksService.
func NewIdsecCmgrNetworksService(authenticators ...auth.IdsecAuth) (*IdsecCmgrNetworksService, error) {
	networksService := &IdsecCmgrNetworksService{}
	var networksServiceInterface services.IdsecService = networksService
	baseService, err := services.NewIdsecBaseService(networksServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "connectormanagement", ".", "", networksService.refreshAuth)
	if err != nil {
		return nil, err
	}

	networksService.IdsecBaseService = baseService
	networksService.IdsecISPBaseService = ispBaseService
	return networksService, nil
}

func (s *IdsecCmgrNetworksService) refreshAuth(client *common.IdsecClient) error {
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
					if _, ok := resourceItem.(map[string]interface{})["assigned_pools"]; ok {
						for _, pool := range resourceItem.(map[string]interface{})["assigned_pools"].([]interface{}) {
							pool.(map[string]interface{})["pool_id"] = pool.(map[string]interface{})["id"]
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

// Create adds a new network to the connector management service.
func (s *IdsecCmgrNetworksService) Create(addNetwork *networksmodels.IdsecCmgrAddNetwork) (*networksmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Adding network [%s]", addNetwork.Name)
	var addNetworkJSON map[string]interface{}
	err := mapstructure.Decode(addNetwork, &addNetworkJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.ISPClient().Post(context.Background(), networksURL, addNetworkJSON)
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
		return nil, fmt.Errorf("failed to add network - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	networkJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	networkJSONMap := networkJSON.(map[string]interface{})
	networkJSONMap["network_id"] = networkJSONMap["id"]
	var network networksmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// Update updates an existing network in the connector management service.
func (s *IdsecCmgrNetworksService) Update(updateNetwork *networksmodels.IdsecCmgrUpdateNetwork) (*networksmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Updating network [%s]", updateNetwork.NetworkID)
	if updateNetwork.Name == "" {
		s.Logger.Info("Nothing to update")
		return s.Get(&networksmodels.IdsecCmgrGetNetwork{NetworkID: updateNetwork.NetworkID})
	}
	var updateNetworkJSON map[string]interface{}
	err := mapstructure.Decode(updateNetwork, &updateNetworkJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.ISPClient().Patch(context.Background(), fmt.Sprintf(networkURL, updateNetwork.NetworkID), updateNetworkJSON)
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
		return nil, fmt.Errorf("failed to update network - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	networkJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	networkJSONMap := networkJSON.(map[string]interface{})
	networkJSONMap["network_id"] = networkJSONMap["id"]
	var network networksmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// Delete deletes an existing network from the connector management service.
func (s *IdsecCmgrNetworksService) Delete(deleteNetwork *networksmodels.IdsecCmgrDeleteNetwork) error {
	s.Logger.Info("Deleting network [%s]", deleteNetwork.NetworkID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(networkURL, deleteNetwork.NetworkID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete network - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// List lists all networks in the connector management service.
func (s *IdsecCmgrNetworksService) List() (<-chan *IdsecCmgrNetworkPage, error) {
	s.Logger.Info("Listing all networks")
	return listWithCommonFilter[networksmodels.IdsecCmgrNetwork](
		s.Logger,
		s.ISPClient(),
		"networks",
		networksURL,
		nil,
		map[string]string{
			"id": "network_id",
		},
	)
}

// ListBy lists networks by the specified filter in the connector management service.
func (s *IdsecCmgrNetworksService) ListBy(networksFilter *networksmodels.IdsecCmgrNetworksFilter) (<-chan *IdsecCmgrNetworkPage, error) {
	s.Logger.Info("Listing networks by filter [%v]", networksFilter)
	return listWithCommonFilter[networksmodels.IdsecCmgrNetwork](
		s.Logger,
		s.ISPClient(),
		"networks",
		networksURL,
		&networksFilter.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "network_id",
		},
	)
}

// Get retrieves a specific network by its ID from the connector management service.
func (s *IdsecCmgrNetworksService) Get(getNetwork *networksmodels.IdsecCmgrGetNetwork) (*networksmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Retrieving network [%s]", getNetwork.NetworkID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(networkURL, getNetwork.NetworkID), nil)
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
		return nil, fmt.Errorf("failed to retrieve network - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	networkJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	networkJSONMap := networkJSON.(map[string]interface{})
	networkJSONMap["network_id"] = networkJSONMap["id"]
	var network networksmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// Stats retrieves statistics about networks in the connector management service.
func (s *IdsecCmgrNetworksService) Stats() (*networksmodels.IdsecCmgrNetworksStats, error) {
	s.Logger.Info("Retrieving networks stats")
	networksChan, err := s.List()
	if err != nil {
		return nil, err
	}
	networks := make([]*networksmodels.IdsecCmgrNetwork, 0)
	for page := range networksChan {
		networks = append(networks, page.Items...)
	}
	var networksStats networksmodels.IdsecCmgrNetworksStats
	networksStats.NetworksCount = len(networks)
	networksStats.PoolsCountPerNetwork = make(map[string]int)
	for _, network := range networks {
		networksStats.PoolsCountPerNetwork[network.Name] = len(network.AssignedPools)
	}
	return &networksStats, nil
}

// ServiceConfig returns the service configuration for the IdsecCmgrNetworksService.
func (s *IdsecCmgrNetworksService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
