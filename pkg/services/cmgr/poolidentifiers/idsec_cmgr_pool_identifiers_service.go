package poolidentifiers

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
	identifiersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers/models"
	poolsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools/models"
)

const (
	poolIdentifiersURL     = "api/pool-service/pools/%s/identifiers"
	poolIdentifiersBulkURL = "api/pool-service/pools/%s/identifiers-bulk"
	poolIdentifierURL      = "api/pool-service/pools/%s/identifiers/%s"
)

// IdsecCmgrPoolIdentifierPage is a page of IdsecCmgrPoolIdentifier items.
type IdsecCmgrPoolIdentifierPage = common.IdsecPage[identifiersmodels.IdsecCmgrPoolIdentifier]

// IdsecCmgrPoolIdentifiersService is the service for managing CMGR pool identifiers.
type IdsecCmgrPoolIdentifiersService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCmgrPoolIdentifiersService creates a new instance of IdsecCmgrPoolIdentifiersService.
func NewIdsecCmgrPoolIdentifiersService(authenticators ...auth.IdsecAuth) (*IdsecCmgrPoolIdentifiersService, error) {
	identifiersService := &IdsecCmgrPoolIdentifiersService{}
	var identifiersServiceInterface services.IdsecService = identifiersService
	baseService, err := services.NewIdsecBaseService(identifiersServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "connectormanagement", ".", "", identifiersService.refreshAuth)
	if err != nil {
		return nil, err
	}

	identifiersService.IdsecBaseService = baseService
	identifiersService.IdsecISPBaseService = ispBaseService
	return identifiersService, nil
}

func (s *IdsecCmgrPoolIdentifiersService) refreshAuth(client *common.IdsecClient) error {
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

// Create adds a new identifier to a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) Create(addPoolIdentifier *identifiersmodels.IdsecCmgrAddPoolSingleIdentifier) (*identifiersmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Adding pool identifier [%v]", addPoolIdentifier)
	var addPoolIdentifierJSON map[string]interface{}
	err := mapstructure.Decode(addPoolIdentifier, &addPoolIdentifierJSON)
	if err != nil {
		return nil, err
	}
	delete(addPoolIdentifierJSON, "pool_id")
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(poolIdentifiersURL, addPoolIdentifier.PoolID), addPoolIdentifierJSON)
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
	var poolIdentifier identifiersmodels.IdsecCmgrPoolIdentifier
	err = mapstructure.Decode(poolIdentifierJSONMap, &poolIdentifier)
	if err != nil {
		return nil, err
	}
	return &poolIdentifier, nil
}

// BulkCreate adds multiple identifiers to a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) BulkCreate(addPoolIdentifiers *identifiersmodels.IdsecCmgrAddPoolBulkIdentifier) (*identifiersmodels.IdsecCmgrPoolIdentifiers, error) {
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
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(poolIdentifiersBulkURL, addPoolIdentifiers.PoolID), payload)
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
	var bulkResponses *poolsmodels.IdsecCmgrBulkResponses
	err = mapstructure.Decode(bulkResponsesJSON, &bulkResponses)
	if err != nil {
		return nil, fmt.Errorf("failed to decode bulk responses: %w", err)
	}
	identifiers := make([]*identifiersmodels.IdsecCmgrPoolIdentifier, 0)
	for _, identifierResponse := range bulkResponses.Responses {
		if identifierResponse.StatusCode != http.StatusCreated {
			return nil, fmt.Errorf("failed to add pool identifiers bulk - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
		identifierResponse.Body["identifier_id"] = identifierResponse.Body["id"]
		var identifier identifiersmodels.IdsecCmgrPoolIdentifier
		err := mapstructure.Decode(identifierResponse.Body, &identifier)
		if err != nil {
			return nil, fmt.Errorf("failed to decode identifier response body: %w", err)
		}
		identifiers = append(identifiers, &identifier)
	}
	return &identifiersmodels.IdsecCmgrPoolIdentifiers{Identifiers: identifiers}, nil
}

// Update updates an existing identifier in a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) Update(updatePoolIdentifier *identifiersmodels.IdsecCmgrUpdatePoolIdentifier) (*identifiersmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Updating pool identifier [%s] from pool [%s]", updatePoolIdentifier.IdentifierID, updatePoolIdentifier.PoolID)
	err := s.Delete(&identifiersmodels.IdsecCmgrDeletePoolSingleIdentifier{
		IdentifierID: updatePoolIdentifier.IdentifierID,
		PoolID:       updatePoolIdentifier.PoolID,
	})
	if err != nil {
		return nil, err
	}
	return s.Create(&identifiersmodels.IdsecCmgrAddPoolSingleIdentifier{
		Type:   updatePoolIdentifier.Type,
		Value:  updatePoolIdentifier.Value,
		PoolID: updatePoolIdentifier.PoolID,
	})
}

// Delete deletes an identifier from a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) Delete(deletePoolIdentifier *identifiersmodels.IdsecCmgrDeletePoolSingleIdentifier) error {
	s.Logger.Info("Deleting pool identifier [%s]", deletePoolIdentifier.IdentifierID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(poolIdentifierURL, deletePoolIdentifier.PoolID, deletePoolIdentifier.IdentifierID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete pool identifier - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// BulkDelete deletes multiple identifiers from a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) BulkDelete(deletePoolIdentifiers *identifiersmodels.IdsecCmgrDeletePoolBulkIdentifier) error {
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
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(poolIdentifiersBulkURL, deletePoolIdentifiers.PoolID), payload)
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
	var bulkResponses poolsmodels.IdsecCmgrBulkResponses
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

// List lists all identifiers in a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) List(listPoolIdentifiers *identifiersmodels.IdsecCmgrListPoolIdentifiers) (<-chan *IdsecCmgrPoolIdentifierPage, error) {
	s.Logger.Info("Listing pool identifiers [%v]", listPoolIdentifiers)
	return listWithCommonFilter[identifiersmodels.IdsecCmgrPoolIdentifier](
		s.Logger,
		s.ISPClient(),
		"pool identifiers",
		fmt.Sprintf(poolIdentifiersURL, listPoolIdentifiers.PoolID),
		nil,
		map[string]string{
			"id": "identifier_id",
		},
	)
}

// ListBy lists identifiers by the specified filter in a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) ListBy(identifiersFilters *identifiersmodels.IdsecCmgrPoolIdentifiersFilter) (<-chan *IdsecCmgrPoolIdentifierPage, error) {
	s.Logger.Info("Listing pool identifiers by filter [%v]", identifiersFilters)
	return listWithCommonFilter[identifiersmodels.IdsecCmgrPoolIdentifier](
		s.Logger,
		s.ISPClient(),
		"pool identifiers",
		fmt.Sprintf(poolIdentifiersURL, identifiersFilters.PoolID),
		&identifiersFilters.IdsecCmgrPoolsCommonFilter,
		map[string]string{
			"id": "identifier_id",
		},
	)
}

// Get retrieves a specific identifier by its ID from a specific pool in the connector management service.
func (s *IdsecCmgrPoolIdentifiersService) Get(getIdentifier *identifiersmodels.IdsecCmgrGetPoolIdentifier) (*identifiersmodels.IdsecCmgrPoolIdentifier, error) {
	s.Logger.Info("Retrieving pool identifier [%s] from pool [%s]", getIdentifier.IdentifierID, getIdentifier.PoolID)
	identifiers, err := s.List(&identifiersmodels.IdsecCmgrListPoolIdentifiers{PoolID: getIdentifier.PoolID})
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

// ServiceConfig returns the service configuration for the IdsecCmgrPoolIdentifiersService.
func (s *IdsecCmgrPoolIdentifiersService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
