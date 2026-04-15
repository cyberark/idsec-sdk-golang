package pools

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
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
)

const (
	poolsURL = "api/pool-service/pools"
	poolURL  = "api/pool-service/pools/%s"
)

// IdsecCmgrPoolPage is a page of IdsecCmgrPool items.
type IdsecCmgrPoolPage = common.IdsecPage[poolsmodels.IdsecCmgrPool]

// IdsecCmgrPoolsService is the service for managing CMGR pools.
type IdsecCmgrPoolsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCmgrPoolsService creates a new instance of IdsecCmgrPoolsService.
func NewIdsecCmgrPoolsService(authenticators ...auth.IdsecAuth) (*IdsecCmgrPoolsService, error) {
	poolsService := &IdsecCmgrPoolsService{}
	var poolsServiceInterface services.IdsecService = poolsService
	baseService, err := services.NewIdsecBaseService(poolsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "connectormanagement", ".", "", poolsService.refreshAuth)
	if err != nil {
		return nil, err
	}

	poolsService.IdsecBaseService = baseService
	poolsService.IdsecISPBaseService = ispBaseService
	return poolsService, nil
}

func (s *IdsecCmgrPoolsService) refreshAuth(client *common.IdsecClient) error {
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

// Create adds a new pool to the connector management service.
func (s *IdsecCmgrPoolsService) Create(addPool *poolsmodels.IdsecCmgrAddPool) (*poolsmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Adding pool [%s]", addPool.Name)
	var addPoolJSON map[string]interface{}
	err := mapstructure.Decode(addPool, &addPoolJSON)
	if err != nil {
		return nil, err
	}
	if len(addPool.AssignedNetworkIDs) == 0 {
		return nil, fmt.Errorf("no networks assigned to the pool")
	}
	response, err := s.ISPClient().Post(context.Background(), poolsURL, addPoolJSON)
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
		return nil, fmt.Errorf("failed to add pool - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	poolJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	poolJSONMap := poolJSON.(map[string]interface{})
	poolJSONMap["pool_id"] = poolJSONMap["id"]
	var pool poolsmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// Update updates an existing pool in the connector management service.
func (s *IdsecCmgrPoolsService) Update(updatePool *poolsmodels.IdsecCmgrUpdatePool) (*poolsmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Updating pool [%s]", updatePool.PoolID)
	if updatePool.Name == "" && updatePool.Description == "" && updatePool.AssignedNetworkIDs == nil {
		s.Logger.Info("Nothing to update")
		return s.Get(&poolsmodels.IdsecCmgrGetPool{PoolID: updatePool.PoolID})
	}
	var updatePoolJSON map[string]interface{}
	err := mapstructure.Decode(updatePool, &updatePoolJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.ISPClient().Patch(context.Background(), fmt.Sprintf(poolURL, updatePool.PoolID), updatePoolJSON)
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
		return nil, fmt.Errorf("failed to update pool - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	poolJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	poolJSONMap := poolJSON.(map[string]interface{})
	poolJSONMap["pool_id"] = poolJSONMap["id"]
	var pool poolsmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// Delete deletes an existing pool from the connector management service.
func (s *IdsecCmgrPoolsService) Delete(deletePool *poolsmodels.IdsecCmgrDeletePool) error {
	s.Logger.Info("Deleting pool [%s]", deletePool.PoolID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(poolURL, deletePool.PoolID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete pool - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// List lists all pools in the connector management service.
func (s *IdsecCmgrPoolsService) List() (<-chan *IdsecCmgrPoolPage, error) {
	s.Logger.Info("Listing all pools")
	return listWithCommonFilter[poolsmodels.IdsecCmgrPool](
		s.Logger,
		s.ISPClient(),
		"pools",
		poolsURL,
		nil,
		map[string]string{
			"id": "pool_id",
		},
	)
}

// ListBy lists pools by the specified filter in the connector management service.
func (s *IdsecCmgrPoolsService) ListBy(poolsFilter *poolsmodels.IdsecCmgrPoolsFilter) (<-chan *IdsecCmgrPoolPage, error) {
	s.Logger.Info("Listing pools by filter [%v]", poolsFilter)
	return listWithCommonFilter[poolsmodels.IdsecCmgrPool](
		s.Logger,
		s.ISPClient(),
		"pools",
		poolsURL,
		&poolsFilter.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "pool_id",
		},
	)
}

// Get retrieves a specific pool by its ID from the connector management service.
func (s *IdsecCmgrPoolsService) Get(getPool *poolsmodels.IdsecCmgrGetPool) (*poolsmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Retrieving pool [%s]", getPool.PoolID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(poolURL, getPool.PoolID), nil)
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
		return nil, fmt.Errorf("failed to retrieve pool - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	poolJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	poolJSONMap := poolJSON.(map[string]interface{})
	poolJSONMap["pool_id"] = poolJSONMap["id"]
	var pool poolsmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// Stats retrieves statistics about pools in the connector management service.
func (s *IdsecCmgrPoolsService) Stats() (*poolsmodels.IdsecCmgrPoolsStats, error) {
	s.Logger.Info("Retrieving pools stats")
	poolsChan, err := s.List()
	if err != nil {
		return nil, err
	}
	pools := make([]*poolsmodels.IdsecCmgrPool, 0)
	for page := range poolsChan {
		pools = append(pools, page.Items...)
	}
	var poolsStats poolsmodels.IdsecCmgrPoolsStats
	poolsStats.PoolsCount = len(pools)
	poolsStats.NetworksCountPerPool = make(map[string]int)
	poolsStats.IdentifiersCountPerPool = make(map[string]int)
	poolsStats.ComponentsCountPerPool = make(map[string]map[string]int)
	for _, pool := range pools {
		poolsStats.NetworksCountPerPool[pool.Name] = len(pool.AssignedNetworkIDs)
		poolsStats.IdentifiersCountPerPool[pool.Name] = pool.IdentifiersCount
		poolsStats.ComponentsCountPerPool[pool.Name] = pool.ComponentsCount
	}
	return &poolsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecCmgrPoolsService.
func (s *IdsecCmgrPoolsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
