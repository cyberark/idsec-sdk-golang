package cmgr

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	cmgrmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/models"

	"io"
	"net/http"
)

const (
	networksURL            = "api/pool-service/networks"
	networkURL             = "api/pool-service/networks/%s"
	poolsURL               = "api/pool-service/pools"
	poolURL                = "api/pool-service/pools/%s"
	poolIdentifiersURL     = "api/pool-service/pools/%s/identifiers"
	poolIdentifiersBulkURL = "api/pool-service/pools/%s/identifiers-bulk"
	poolIdentifierURL      = "api/pool-service/pools/%s/identifiers/%s"
	poolsComponentsURL     = "api/pool-service/pools/components"
	poolComponentURL       = "api/pool-service/pools/%s/components/%s"
)

// IdsecCmgrNetworkPage is a page of IdsecCmgrNetwork items.
type IdsecCmgrNetworkPage = common.IdsecPage[cmgrmodels.IdsecCmgrNetwork]

// IdsecCmgrPoolPage is a page of IdsecCmgrPool items.
type IdsecCmgrPoolPage = common.IdsecPage[cmgrmodels.IdsecCmgrPool]

// IdsecCmgrPoolIdentifierPage is a page of IdsecCmgrPoolIdentifier items.
type IdsecCmgrPoolIdentifierPage = common.IdsecPage[cmgrmodels.IdsecCmgrPoolIdentifier]

// IdsecCmgrPoolComponentPage is a page of IdsecCmgrPoolComponent items.
type IdsecCmgrPoolComponentPage = common.IdsecPage[cmgrmodels.IdsecCmgrPoolComponent]

// IdsecCmgrService is the service for managing connector management.
type IdsecCmgrService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecCmgrService creates a new instance of IdsecCmgrService.
func NewIdsecCmgrService(authenticators ...auth.IdsecAuth) (*IdsecCmgrService, error) {
	cmgrService := &IdsecCmgrService{}
	var cmgrServiceInterface services.IdsecService = cmgrService
	baseService, err := services.NewIdsecBaseService(cmgrServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "connectormanagement", ".", "", cmgrService.refreshCmgrAuth)
	if err != nil {
		return nil, err
	}
	cmgrService.client = client
	cmgrService.ispAuth = ispAuth
	cmgrService.IdsecBaseService = baseService
	return cmgrService, nil
}

func (s *IdsecCmgrService) refreshCmgrAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func listCommonPools[PageItemType any](
	logger *common.IdsecLogger,
	client *isp.IdsecISPServiceClient,
	name string, route string,
	commonFilter *cmgrmodels.IdsecCmgrPoolsCommonFilter,
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

// AddNetwork adds a new network to the connector management service.
func (s *IdsecCmgrService) AddNetwork(addNetwork *cmgrmodels.IdsecCmgrAddNetwork) (*cmgrmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Adding network [%s]", addNetwork.Name)
	var addNetworkJSON map[string]interface{}
	err := mapstructure.Decode(addNetwork, &addNetworkJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Post(context.Background(), networksURL, addNetworkJSON)
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
	var network cmgrmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// UpdateNetwork updates an existing network in the connector management service.
func (s *IdsecCmgrService) UpdateNetwork(updateNetwork *cmgrmodels.IdsecCmgrUpdateNetwork) (*cmgrmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Updating network [%s]", updateNetwork.NetworkID)
	if updateNetwork.Name == "" {
		s.Logger.Info("Nothing to update")
		return s.Network(&cmgrmodels.IdsecCmgrGetNetwork{NetworkID: updateNetwork.NetworkID})
	}
	var updateNetworkJSON map[string]interface{}
	err := mapstructure.Decode(updateNetwork, &updateNetworkJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Patch(context.Background(), fmt.Sprintf(networkURL, updateNetwork.NetworkID), updateNetworkJSON)
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
	var network cmgrmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// DeleteNetwork deletes an existing network from the connector management service.
func (s *IdsecCmgrService) DeleteNetwork(deleteNetwork *cmgrmodels.IdsecCmgrDeleteNetwork) error {
	s.Logger.Info("Deleting network [%s]", deleteNetwork.NetworkID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(networkURL, deleteNetwork.NetworkID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete network - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ListNetworks lists all networks in the connector management service.
func (s *IdsecCmgrService) ListNetworks() (<-chan *IdsecCmgrNetworkPage, error) {
	s.Logger.Info("Listing all networks")
	return listCommonPools[cmgrmodels.IdsecCmgrNetwork](
		s.Logger,
		s.client,
		"networks",
		networksURL,
		nil,
		map[string]string{
			"id": "network_id",
		},
	)
}

// ListNetworksBy lists networks by the specified filter in the connector management service.
func (s *IdsecCmgrService) ListNetworksBy(networksFilter *cmgrmodels.IdsecCmgrNetworksFilter) (<-chan *IdsecCmgrNetworkPage, error) {
	s.Logger.Info("Listing networks by filter [%v]", networksFilter)
	return listCommonPools[cmgrmodels.IdsecCmgrNetwork](
		s.Logger,
		s.client,
		"networks",
		networksURL,
		&networksFilter.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "network_id",
		},
	)
}

// Network retrieves a specific network by its ID from the connector management service.
func (s *IdsecCmgrService) Network(getNetwork *cmgrmodels.IdsecCmgrGetNetwork) (*cmgrmodels.IdsecCmgrNetwork, error) {
	s.Logger.Info("Retrieving network [%s]", getNetwork.NetworkID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(networkURL, getNetwork.NetworkID), nil)
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
	var network cmgrmodels.IdsecCmgrNetwork
	err = mapstructure.Decode(networkJSONMap, &network)
	if err != nil {
		return nil, err
	}
	return &network, nil
}

// NetworksStats retrieves statistics about networks in the connector management service.
func (s *IdsecCmgrService) NetworksStats() (*cmgrmodels.IdsecCmgrNetworksStats, error) {
	s.Logger.Info("Retrieving networks stats")
	networksChan, err := s.ListNetworks()
	if err != nil {
		return nil, err
	}
	networks := make([]*cmgrmodels.IdsecCmgrNetwork, 0)
	for page := range networksChan {
		networks = append(networks, page.Items...)
	}
	var networksStats cmgrmodels.IdsecCmgrNetworksStats
	networksStats.NetworksCount = len(networks)
	networksStats.PoolsCountPerNetwork = make(map[string]int)
	for _, network := range networks {
		networksStats.PoolsCountPerNetwork[network.Name] = len(network.AssignedPools)
	}
	return &networksStats, nil
}

// AddPool adds a new pool to the connector management service.
func (s *IdsecCmgrService) AddPool(addPool *cmgrmodels.IdsecCmgrAddPool) (*cmgrmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Adding pool [%s]", addPool.Name)
	var addPoolJSON map[string]interface{}
	err := mapstructure.Decode(addPool, &addPoolJSON)
	if err != nil {
		return nil, err
	}
	if len(addPool.AssignedNetworkIDs) == 0 {
		return nil, fmt.Errorf("no networks assigned to the pool")
	}
	response, err := s.client.Post(context.Background(), poolsURL, addPoolJSON)
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
	var pool cmgrmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// UpdatePool updates an existing pool in the connector management service.
func (s *IdsecCmgrService) UpdatePool(updatePool *cmgrmodels.IdsecCmgrUpdatePool) (*cmgrmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Updating pool [%s]", updatePool.PoolID)
	if updatePool.Name == "" && updatePool.Description == "" && updatePool.AssignedNetworkIDs == nil {
		s.Logger.Info("Nothing to update")
		return s.Pool(&cmgrmodels.IdsecCmgrGetPool{PoolID: updatePool.PoolID})
	}
	var updatePoolJSON map[string]interface{}
	err := mapstructure.Decode(updatePool, &updatePoolJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Patch(context.Background(), fmt.Sprintf(poolURL, updatePool.PoolID), updatePoolJSON)
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
	var pool cmgrmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// DeletePool deletes an existing pool from the connector management service.
func (s *IdsecCmgrService) DeletePool(deletePool *cmgrmodels.IdsecCmgrDeletePool) error {
	s.Logger.Info("Deleting pool [%s]", deletePool.PoolID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(poolURL, deletePool.PoolID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete pool - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ListPools lists all pools in the connector management service.
func (s *IdsecCmgrService) ListPools() (<-chan *IdsecCmgrPoolPage, error) {
	s.Logger.Info("Listing all pools")
	return listCommonPools[cmgrmodels.IdsecCmgrPool](
		s.Logger,
		s.client,
		"pools",
		poolsURL,
		nil,
		map[string]string{
			"id": "pool_id",
		},
	)
}

// ListPoolsBy lists pools by the specified filter in the connector management service.
func (s *IdsecCmgrService) ListPoolsBy(poolsFilter *cmgrmodels.IdsecCmgrPoolsFilter) (<-chan *IdsecCmgrPoolPage, error) {
	s.Logger.Info("Listing pools by filter [%v]", poolsFilter)
	return listCommonPools[cmgrmodels.IdsecCmgrPool](
		s.Logger,
		s.client,
		"pools",
		poolsURL,
		&poolsFilter.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "pool_id",
		},
	)
}

// Pool retrieves a specific pool by its ID from the connector management service.
func (s *IdsecCmgrService) Pool(getPool *cmgrmodels.IdsecCmgrGetPool) (*cmgrmodels.IdsecCmgrPool, error) {
	s.Logger.Info("Retrieving pool [%s]", getPool.PoolID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(poolURL, getPool.PoolID), nil)
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
	var pool cmgrmodels.IdsecCmgrPool
	err = mapstructure.Decode(poolJSONMap, &pool)
	if err != nil {
		return nil, err
	}
	return &pool, nil
}

// PoolsStats retrieves statistics about pools in the connector management service.
func (s *IdsecCmgrService) PoolsStats() (*cmgrmodels.IdsecCmgrPoolsStats, error) {
	s.Logger.Info("Retrieving pools stats")
	poolsChan, err := s.ListPools()
	if err != nil {
		return nil, err
	}
	pools := make([]*cmgrmodels.IdsecCmgrPool, 0)
	for page := range poolsChan {
		pools = append(pools, page.Items...)
	}
	var poolsStats cmgrmodels.IdsecCmgrPoolsStats
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

// AddPoolIdentifier adds a new identifier to a specific pool in the connector management service.
func (s *IdsecCmgrService) AddPoolIdentifier(addPoolIdentifier *cmgrmodels.IdsecCmgrAddPoolSingleIdentifier) (*cmgrmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Adding pool identifier [%v]", addPoolIdentifier)
	var addPoolIdentifierJSON map[string]interface{}
	err := mapstructure.Decode(addPoolIdentifier, &addPoolIdentifierJSON)
	if err != nil {
		return nil, err
	}
	delete(addPoolIdentifierJSON, "pool_id")
	response, err := s.client.Post(context.Background(), fmt.Sprintf(poolIdentifiersURL, addPoolIdentifier.PoolID), addPoolIdentifierJSON)
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
		return nil, fmt.Errorf("failed to add pool identifier - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	poolIdentifierJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	poolIdentifierJSONMap := poolIdentifierJSON.(map[string]interface{})
	poolIdentifierJSONMap["identifier_id"] = poolIdentifierJSONMap["id"]
	var poolIdentifier cmgrmodels.IdsecCmgrPoolIdentifier
	err = mapstructure.Decode(poolIdentifierJSONMap, &poolIdentifier)
	if err != nil {
		return nil, err
	}
	return &poolIdentifier, nil
}

// AddPoolIdentifiers adds multiple identifiers to a specific pool in the connector management service.
func (s *IdsecCmgrService) AddPoolIdentifiers(addPoolIdentifiers *cmgrmodels.IdsecCmgrAddPoolBulkIdentifier) (*cmgrmodels.IdsecCmgrPoolIdentifiers, error) {
	s.Logger.Info("Adding pool identifiers [%v]", addPoolIdentifiers)
	requests := make(map[string]interface{})
	for index, identifier := range addPoolIdentifiers.Identifiers {
		identifierMap := make(map[string]interface{})
		err := mapstructure.Decode(identifier, &identifierMap)
		if err != nil {
			return nil, fmt.Errorf("failed to decode identifier: %w", err)
		}
		requests[fmt.Sprintf("%d", index+1)] = identifierMap
	}
	payload := map[string]interface{}{
		"requests": requests,
	}
	response, err := s.client.Post(context.Background(), fmt.Sprintf(poolIdentifiersBulkURL, addPoolIdentifiers.PoolID), payload)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusMultiStatus {
		return nil, fmt.Errorf("failed to add pool identifiers - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	bulkResponsesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var bulkResponses *cmgrmodels.IdsecCmgrBulkResponses
	err = mapstructure.Decode(bulkResponsesJSON, &bulkResponses)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bulk responses: %w", err)
	}
	identifiers := make([]*cmgrmodels.IdsecCmgrPoolIdentifier, 0)
	for _, identifierResponse := range bulkResponses.Responses {
		if identifierResponse.StatusCode != http.StatusCreated {
			return nil, fmt.Errorf("failed to add pool identifiers bulk - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
		identifierResponse.Body["identifier_id"] = identifierResponse.Body["id"]
		var identifier cmgrmodels.IdsecCmgrPoolIdentifier
		err := mapstructure.Decode(identifierResponse.Body, &identifier)
		if err != nil {
			return nil, fmt.Errorf("failed to decode identifier response body: %w", err)
		}
		identifiers = append(identifiers, &identifier)
	}
	return &cmgrmodels.IdsecCmgrPoolIdentifiers{Identifiers: identifiers}, nil
}

// UpdatePoolIdentifier updates an existing identifier in a specific pool in the connector management service.
func (s *IdsecCmgrService) UpdatePoolIdentifier(updatePoolIdentifier *cmgrmodels.IdsecCmgrUpdatePoolIdentifier) (*cmgrmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Updating pool identifier [%s] from pool [%s]", updatePoolIdentifier.IdentifierID, updatePoolIdentifier.PoolID)
	err := s.DeletePoolIdentifier(&cmgrmodels.IdsecCmgrDeletePoolSingleIdentifier{
		IdentifierID: updatePoolIdentifier.IdentifierID,
		PoolID:       updatePoolIdentifier.PoolID,
	})
	if err != nil {
		return nil, err
	}
	return s.AddPoolIdentifier(&cmgrmodels.IdsecCmgrAddPoolSingleIdentifier{
		Type:   updatePoolIdentifier.Type,
		Value:  updatePoolIdentifier.Value,
		PoolID: updatePoolIdentifier.PoolID,
	})
}

// DeletePoolIdentifier deletes an identifier from a specific pool in the connector management service.
func (s *IdsecCmgrService) DeletePoolIdentifier(deletePoolIdentifier *cmgrmodels.IdsecCmgrDeletePoolSingleIdentifier) error {
	s.Logger.Info("Deleting pool identifier [%s]", deletePoolIdentifier.IdentifierID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(poolIdentifierURL, deletePoolIdentifier.PoolID, deletePoolIdentifier.IdentifierID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete pool identifier - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// DeletePoolIdentifiers deletes multiple identifiers from a specific pool in the connector management service.
func (s *IdsecCmgrService) DeletePoolIdentifiers(deletePoolIdentifiers *cmgrmodels.IdsecCmgrDeletePoolBulkIdentifier) error {
	s.Logger.Info("Deleting pool identifiers [%s]", deletePoolIdentifiers.PoolID)
	requests := make(map[string]interface{})
	for index, identifier := range deletePoolIdentifiers.Identifiers {
		identifierMap := make(map[string]interface{})
		err := mapstructure.Decode(identifier, &identifierMap)
		if err != nil {
			return fmt.Errorf("failed to decode identifier: %w", err)
		}
		requests[fmt.Sprintf("%d", index+1)] = identifierMap
	}
	payload := map[string]interface{}{
		"requests": requests,
	}
	response, err := s.client.Post(context.Background(), fmt.Sprintf(poolIdentifiersBulkURL, deletePoolIdentifiers.PoolID), payload)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusMultiStatus {
		return fmt.Errorf("failed to delete pool identifiers - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	bulkResponsesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return fmt.Errorf("failed to decode bulk responses: %w", err)
	}
	var bulkResponses cmgrmodels.IdsecCmgrBulkResponses
	err = mapstructure.Decode(bulkResponsesJSON, &bulkResponses)
	if err != nil {
		return fmt.Errorf("failed to decode bulk responses: %w", err)
	}
	for _, identifierResponse := range bulkResponses.Responses {
		if identifierResponse.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to delete pool identifiers - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
	}
	return nil
}

// ListPoolIdentifiers lists all identifiers in a specific pool in the connector management service.
func (s *IdsecCmgrService) ListPoolIdentifiers(listPoolIdentifiers *cmgrmodels.IdsecCmgrListPoolIdentifiers) (<-chan *IdsecCmgrPoolIdentifierPage, error) {
	s.Logger.Info("Listing pool identifiers [%v]", listPoolIdentifiers)
	return listCommonPools[cmgrmodels.IdsecCmgrPoolIdentifier](
		s.Logger,
		s.client,
		"pool identifiers",
		fmt.Sprintf(poolIdentifiersURL, listPoolIdentifiers.PoolID),
		nil,
		map[string]string{
			"id": "identifier_id",
		},
	)
}

// ListPoolIdentifiersBy lists identifiers by the specified filter in a specific pool in the connector management service.
func (s *IdsecCmgrService) ListPoolIdentifiersBy(identifiersFilters *cmgrmodels.IdsecCmgrPoolIdentifiersFilter) (<-chan *IdsecCmgrPoolIdentifierPage, error) {
	s.Logger.Info("Listing pool identifiers by filter [%v]", identifiersFilters)
	return listCommonPools[cmgrmodels.IdsecCmgrPoolIdentifier](
		s.Logger,
		s.client,
		"pool identifiers",
		fmt.Sprintf(poolIdentifiersURL, identifiersFilters.PoolID),
		&identifiersFilters.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "identifier_id",
		},
	)
}

// PoolIdentifier retrieves a specific identifier by its ID from a specific pool in the connector management service.
func (s *IdsecCmgrService) PoolIdentifier(getIdentifier *cmgrmodels.IdsecCmgrGetPoolIdentifier) (*cmgrmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Retrieving pool identifier [%s] from pool [%s]", getIdentifier.IdentifierID, getIdentifier.PoolID)
	identifiers, err := s.ListPoolIdentifiers(&cmgrmodels.IdsecCmgrListPoolIdentifiers{PoolID: getIdentifier.PoolID})
	if err != nil {
		return nil, err
	}
	for page := range identifiers {
		for _, identifier := range page.Items {
			if identifier.IdentifierID == getIdentifier.IdentifierID {
				return identifier, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to retrieve pool identifier - [%s] from pool - [%s]", getIdentifier.IdentifierID, getIdentifier.PoolID)
}

// ListPoolsComponents lists all components in the connector management service.
func (s *IdsecCmgrService) ListPoolsComponents() (<-chan *IdsecCmgrPoolComponentPage, error) {
	s.Logger.Info("Listing pools components")
	return listCommonPools[cmgrmodels.IdsecCmgrPoolComponent](
		s.Logger,
		s.client,
		"pools components",
		poolsComponentsURL,
		nil,
		map[string]string{
			"id": "component_id",
		},
	)
}

// ListPoolsComponentsBy lists components by the specified filter in the connector management service.
func (s *IdsecCmgrService) ListPoolsComponentsBy(componentsFilters *cmgrmodels.IdsecCmgrPoolComponentsFilter) (<-chan *IdsecCmgrPoolComponentPage, error) {
	s.Logger.Info("Listing pools components by filter [%v]", componentsFilters)
	return listCommonPools[cmgrmodels.IdsecCmgrPoolComponent](
		s.Logger,
		s.client,
		"pools components",
		poolsComponentsURL,
		&componentsFilters.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "component_id",
		},
	)
}

// PoolComponent retrieves a specific component by its ID from the connector management service.
func (s *IdsecCmgrService) PoolComponent(getPoolComponent *cmgrmodels.IdsecCmgrGetPoolComponent) (*cmgrmodels.IdsecCmgrPoolComponent, error) {
	s.Logger.Info("Retrieving pool component [%s]", getPoolComponent.ComponentID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(poolComponentURL, getPoolComponent.PoolID, getPoolComponent.ComponentID), nil)
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
	var poolComponent cmgrmodels.IdsecCmgrPoolComponent
	err = mapstructure.Decode(poolComponentJSONMap, &poolComponent)
	if err != nil {
		return nil, err
	}
	return &poolComponent, nil
}

// ServiceConfig returns the service configuration for the IdsecCmgrService.
func (s *IdsecCmgrService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
