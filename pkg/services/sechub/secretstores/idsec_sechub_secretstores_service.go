package secretstores

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mitchellh/mapstructure"
	secretstoresmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

const (
	sechubURL      = "/api/secret-stores"
	secretStoreURL = "/api/secret-stores/%s"
	connStatusURL  = "/api/secret-stores/%s/status/connection"
	stateURL       = "/api/secret-stores/%s/state"
	statesURL      = "/api/secret-stores/states"
)

// immutableFields defines the provider-specific fields that must be stripped from the
// serialized secret store JSON map before sending an update request.
var immutableFields = []string{
	// AWS
	"accountId",
	"regionId",
	// Azure AKV
	"azureVaultUrl",
	// GCP GSM
	"gcpProjectNumber",
	// deprecated - kept for backward compatibility with existing secret stores
	// that might still have these fields, but will not be accepted in update requests
	"gcpPoolProviderId",
	"gcpWorkloadIdentityPoolId",
	"serviceAccountEmail",
	// HashiCorp Vault
	"hashiVaultUrl",
	"mountPath",
}

// IdsecSecHubSecretStoresPage is a page of IdsecSecHubSecretStore items.
type IdsecSecHubSecretStoresPage = common.IdsecPage[secretstoresmodels.IdsecSecHubSecretStore]

// IdsecSecHubSecretStoresService is the service for retrieve Secrets Hub Secret Stores
type IdsecSecHubSecretStoresService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSecHubSecretStoresService creates a new instance of IdsecSecHubSecretStoresService.
func NewIdsecSecHubSecretStoresService(authenticators ...auth.IdsecAuth) (*IdsecSecHubSecretStoresService, error) {
	secretStoresService := &IdsecSecHubSecretStoresService{}
	var secretStoresServiceInterface services.IdsecService = secretStoresService
	baseService, err := services.NewIdsecBaseService(secretStoresServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "secretshub", ".", "", secretStoresService.refreshSecHubAuth)
	if err != nil {
		return nil, err
	}

	secretStoresService.IdsecBaseService = baseService
	secretStoresService.IdsecISPBaseService = ispBaseService
	return secretStoresService, nil
}

func (s *IdsecSecHubSecretStoresService) refreshSecHubAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSecHubSecretStoresService) getSecretStoresWithFilters(
	behavior string,
	filter string,
) (<-chan *IdsecSecHubSecretStoresPage, error) {
	query := map[string]string{}
	if behavior != "" {
		query["behavior"] = behavior
	}
	/*if len(filter) != 0 {
		query["filter"] = filter
	}*/
	results := make(chan *IdsecSecHubSecretStoresPage)
	go func() {
		defer close(results)
		for {
			response, err := s.ISPClient().Get(context.Background(), sechubURL, query)
			if err != nil {
				s.Logger.Error("Failed to list Secret Stores: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list Secret Stores - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}
			resultMap := result.(map[string]interface{})
			var secretStoresJSON []interface{}
			if secretStore, ok := resultMap["secret_stores"]; ok {
				secretStoresJSON = secretStore.([]interface{})
			} else {
				s.Logger.Error("Failed to list Secret Stores, unexpected result")
				return
			}
			for i, secretStore := range secretStoresJSON {
				if secretStoresMap, ok := secretStore.(map[string]interface{}); ok {
					if secretStoreID, ok := secretStoresMap["id"]; ok {
						secretStoresJSON[i].(map[string]interface{})["id"] = secretStoreID
					}
				}
			}
			var secretStores []*secretstoresmodels.IdsecSecHubSecretStore
			if err := mapstructure.Decode(secretStoresJSON, &secretStores); err != nil {
				s.Logger.Error("Failed to validate Secret Stores: %v", err)
				return
			}
			results <- &IdsecSecHubSecretStoresPage{Items: secretStores}
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

// rollbackSecretStoreUpdate rolls back a secret store to its previous state after a failed TF update.
func (s *IdsecSecHubSecretStoresService) rollbackSecretStoreUpdate(
	currentStore *secretstoresmodels.IdsecSecHubSecretStore,
	stateErr error,
) (*secretstoresmodels.IdsecSecHubSecretStore, error) {
	s.Logger.Info("Rolling back updated secret store [%s]", currentStore.Name)

	rollbackStore, rollbackErr := s.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
		ID:          currentStore.ID,
		Name:        currentStore.Name,
		Description: currentStore.Description,
		Data:        &currentStore.Data,
	})
	if rollbackStore != nil {
		rollbackStore.State = currentStore.State
	}

	if rollbackErr != nil {
		return nil, fmt.Errorf("failed to set secret store state for TF update and rollback failed: %w (rollback error: %v)", stateErr, rollbackErr)
	}

	s.Logger.Info("Rolled back successfully secret store [%s]", currentStore.Name)
	return rollbackStore, fmt.Errorf("failed to set secret store state for TF update: %w", stateErr)
}

// stripImmutableFields removes immutable provider-specific fields from the serialized secret store JSON map before sending an update request
func (s *IdsecSecHubSecretStoresService) stripImmutableFields(updateJSON map[string]interface{}) {
	data, ok := updateJSON["data"].(map[string]interface{})
	if !ok {
		return
	}

	for _, field := range immutableFields {
		delete(data, field)
	}
}

// List returns a channel of IdsecSecHubSecretStoresPage containing all Secret Stores.
func (s *IdsecSecHubSecretStoresService) List() (<-chan *IdsecSecHubSecretStoresPage, error) {
	return s.getSecretStoresWithFilters(
		"",
		"",
	)
}

// ListBy returns a channel of IdsecSecHubSecretStoresPage containing secret stores filtered by the given filters.
func (s *IdsecSecHubSecretStoresService) ListBy(secretStoresFilters *secretstoresmodels.IdsecSecHubSecretStoresFilters) (<-chan *IdsecSecHubSecretStoresPage, error) {
	var behavior string
	if secretStoresFilters.Behavior != "" {
		behavior = secretStoresFilters.Behavior
	}
	return s.getSecretStoresWithFilters(
		behavior,
		secretStoresFilters.Filters,
	)
}

// Get returns an individual secret store.
// https://api-docs.cyberark.com/docs/secretshub-api/tw80b23aww65j-get-a-secret-store
func (s *IdsecSecHubSecretStoresService) Get(
	getSecretStore *secretstoresmodels.IdsecSecHubGetSecretStore) (*secretstoresmodels.IdsecSecHubSecretStore, error) {
	s.Logger.Info("Retrieving secret store [%s]", getSecretStore.ID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(secretStoreURL, getSecretStore.ID), nil)
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
		return nil, fmt.Errorf("failed to retrieve secret store - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretStoreJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	secretStoreJSONMap := secretStoreJSON.(map[string]interface{})
	if secretStoreID, ok := secretStoreJSONMap["id"]; ok {
		secretStoreJSONMap["id"] = secretStoreID
	}
	var secretStore secretstoresmodels.IdsecSecHubSecretStore
	err = mapstructure.Decode(secretStoreJSONMap, &secretStore)
	if err != nil {
		return nil, err
	}
	return &secretStore, nil
}

// ConnStatus retrieves the connection status of a secret store.
// https://api-docs.cyberark.com/docs/secretshub-api/b7f2joyxr9ekn-get-connection-status-of-secret-store
func (s *IdsecSecHubSecretStoresService) ConnStatus(
	getSecretStoreConnStatus *secretstoresmodels.IdsecSecHubGetSecretStoreConnectionStatus) (*secretstoresmodels.IdsecSecHubGetSecretStoreConnectionStatusResponse, error) {
	s.Logger.Info("Retrieving secret store connection status [%s]", getSecretStoreConnStatus.ID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(connStatusURL, getSecretStoreConnStatus.ID), nil)
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
		return nil, fmt.Errorf("failed to retrieve secret store connection status - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	connStatusJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var connStatus secretstoresmodels.IdsecSecHubGetSecretStoreConnectionStatusResponse
	err = mapstructure.Decode(connStatusJSON, &connStatus)
	if err != nil {
		return nil, err
	}
	return &connStatus, nil
}

// Create creates a new secret store
// https://api-docs.cyberark.com/docs/secretshub-api/99oqbphsqgomi-create-secret-store
func (s *IdsecSecHubSecretStoresService) Create(secretStore *secretstoresmodels.IdsecSecHubCreateSecretStore) (*secretstoresmodels.IdsecSecHubSecretStore, error) {
	s.Logger.Info("Creating secret store[%s]", secretStore.Name)
	createSecretStoreJSON, err := common.SerializeJSONCamel(secretStore)
	if err != nil {
		return nil, err
	}
	if secretStore.Description != "" {
		delete(createSecretStoreJSON, "description")
		createSecretStoreJSON["description"] = secretStore.Description
	}
	response, err := s.ISPClient().Post(context.Background(), sechubURL, createSecretStoreJSON)
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
		return nil, fmt.Errorf("failed to create secret store - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretStoreJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secretStoreResponse secretstoresmodels.IdsecSecHubSecretStore
	err = mapstructure.Decode(secretStoreJSON, &secretStoreResponse)
	if err != nil {
		return nil, err
	}
	return &secretStoreResponse, nil
}

// Update updates a secret store
// https://api-docs.cyberark.com/docs/secretshub-api/99oqbphsqgomi-create-secret-store
func (s *IdsecSecHubSecretStoresService) Update(secretStore *secretstoresmodels.IdsecSecHubUpdateSecretStore) (*secretstoresmodels.IdsecSecHubSecretStore, error) {
	s.Logger.Info("Updating secret store[%s]", secretStore.Name)
	updateSecretStoreJSON, err := common.SerializeJSONCamel(secretStore)
	if err != nil {
		return nil, err
	}

	s.stripImmutableFields(updateSecretStoreJSON)

	response, err := s.ISPClient().Patch(context.Background(), fmt.Sprintf(secretStoreURL, secretStore.ID), updateSecretStoreJSON)
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
		return nil, fmt.Errorf("failed to update secret store - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretStoreJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secretStoreResponse secretstoresmodels.IdsecSecHubSecretStore
	err = mapstructure.Decode(secretStoreJSON, &secretStoreResponse)
	if err != nil {
		return nil, err
	}
	return &secretStoreResponse, nil
}

// UpdateTf updates a secret store using the Terraform-specific set of steps as the idsec-terraform-provider does not have the option to pass state changes per filed.
func (s *IdsecSecHubSecretStoresService) UpdateTf(secretStore *secretstoresmodels.IdsecSecHubUpdateTfSecretStore) (*secretstoresmodels.IdsecSecHubSecretStore, error) {
	s.Logger.Info("Updating secret store [%s] via Terraform", secretStore.Name)

	currentStore, err := s.Get(&secretstoresmodels.IdsecSecHubGetSecretStore{
		ID: secretStore.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve current secret store for TF update: %w", err)
	}

	updatedStore, err := s.Update(&secretstoresmodels.IdsecSecHubUpdateSecretStore{
		ID:          secretStore.ID,
		Name:        secretStore.Name,
		Description: secretStore.Description,
		Data:        secretStore.Data,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update secret store fields for TF update: %w", err)
	}

	if secretStore.State != currentStore.State {
		action, err := StoreState(secretStore.State).toAction()
		if err != nil {
			return nil, fmt.Errorf("failed to determine action for TF update: %w", err)
		}
		err = s.SetState(&secretstoresmodels.IdsecSecHubSetSecretStoreState{
			ID:     secretStore.ID,
			Action: string(action),
		})
		if err != nil {
			return s.rollbackSecretStoreUpdate(currentStore, err)
		}
		updatedStore.State = secretStore.State
	}

	return updatedStore, nil
}

// SetState sets the state of a secret store.
// https://api-docs.cyberark.com/docs/secretshub-api/qb5o0s8br9nxg-set-secret-store-state
func (s *IdsecSecHubSecretStoresService) SetState(
	setSecretStoreState *secretstoresmodels.IdsecSecHubSetSecretStoreState) error {
	s.Logger.Info("Setting secret store state [%s]", setSecretStoreState.ID)
	bodyMap := map[string]string{
		"action": setSecretStoreState.Action,
	}
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(stateURL, setSecretStoreState.ID), bodyMap)
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
		return fmt.Errorf("failed to set secret store state - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// SetStates sets the state of multiple secret stores
// https://api-docs.cyberark.com/docs/secretshub-api/hxzzult869lhk-set-state-for-multiple-secret-stores
func (s *IdsecSecHubSecretStoresService) SetStates(
	setSecretStoresState *secretstoresmodels.IdsecSecHubSetSecretStoresState) (*secretstoresmodels.IdsecSecHubSetSecretStoresStateResponse, error) {
	s.Logger.Info("Setting multiple secret store states [%s] to [%s]", setSecretStoresState.SecretStoreIDs, setSecretStoresState.Action)
	bodyMap := map[string]interface{}{
		"action":         setSecretStoresState.Action,
		"secretStoreIds": setSecretStoresState.SecretStoreIDs,
	}
	response, err := s.ISPClient().Put(context.Background(), statesURL, bodyMap)
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
		return nil, fmt.Errorf("failed to set secret stores state - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretStoresStateJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secretStoresState secretstoresmodels.IdsecSecHubSetSecretStoresStateResponse
	err = mapstructure.Decode(secretStoresStateJSON, &secretStoresState)
	if err != nil {
		return nil, err
	}
	return &secretStoresState, nil
}

// Delete deletes a specified secret store based on ID
// https://api-docs.cyberark.com/docs/secretshub-api/88xyegf662fxm-delete-secret-store
func (s *IdsecSecHubSecretStoresService) Delete(secretStore *secretstoresmodels.IdsecSecHubDeleteSecretStore) error {
	s.Logger.Info("Deleting secret store")
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(secretStoreURL, secretStore.ID), nil, nil)
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
		return fmt.Errorf("failed to delete secret store - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Stats retrieves statistics about secret stores.
func (s *IdsecSecHubSecretStoresService) Stats() (*secretstoresmodels.IdsecSecHubSecretStoresStats, error) {
	s.Logger.Info("Retrieving secret store stats")
	secretStoresChan, err := s.List()
	if err != nil {
		return nil, err
	}
	secretStores := make([]*secretstoresmodels.IdsecSecHubSecretStore, 0)
	for page := range secretStoresChan {
		secretStores = append(secretStores, page.Items...)
	}
	var secretStoresStats secretstoresmodels.IdsecSecHubSecretStoresStats
	secretStoresStats.SecretStoresCount = len(secretStores)
	secretStoresStats.SecretStoresCountByType = make(map[string]int)
	secretStoresStats.SecretStoresCountByCreator = make(map[string]int)
	for _, secretStore := range secretStores {
		if _, ok := secretStoresStats.SecretStoresCountByCreator[secretStore.CreatedBy]; !ok {
			secretStoresStats.SecretStoresCountByCreator[secretStore.CreatedBy] = 0
		}
		if _, ok := secretStoresStats.SecretStoresCountByType[secretStore.Type]; !ok {
			secretStoresStats.SecretStoresCountByType[secretStore.Type] = 0
		}
		secretStoresStats.SecretStoresCountByType[secretStore.Type]++
		secretStoresStats.SecretStoresCountByCreator[secretStore.CreatedBy]++
	}
	return &secretStoresStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSecHubSecretStoreService.
func (s *IdsecSecHubSecretStoresService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
