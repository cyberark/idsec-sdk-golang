package targetsets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	vmsecrets "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"
	targetsetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/targetsets/models"

	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	targetSetsURL            = "/api/targetsets"
	bulkTargetSetsURL        = "/api/targetsets/bulk"
	targetSetURL             = "/api/targetsets/%s"
	targetSetsCountURL       = "/api/targetsets/target_sets_count"
	targetSetsGetMultipleURL = "/api/targetsets/get_target_sets/%s"
)

// IdsecSIAWorkspacesTargetSetsService is the service for managing target sets in a workspace.
type IdsecSIAWorkspacesTargetSetsService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSIAWorkspacesTargetSetsService creates a new instance of IdsecSIAWorkspacesTargetSetsService.
func NewIdsecSIAWorkspacesTargetSetsService(authenticators ...auth.IdsecAuth) (*IdsecSIAWorkspacesTargetSetsService, error) {
	targetSetsService := &IdsecSIAWorkspacesTargetSetsService{}
	var targetSetsServiceInterface services.IdsecService = targetSetsService
	baseService, err := services.NewIdsecBaseService(targetSetsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", targetSetsService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	targetSetsService.client = client
	targetSetsService.ispAuth = ispAuth
	targetSetsService.IdsecBaseService = baseService
	return targetSetsService, nil
}

func (s *IdsecSIAWorkspacesTargetSetsService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// validateSecretExists checks if a secret with the given ID exists in the tenant.
// This prevents creating target sets with invalid secret references, matching UI behavior.
func (s *IdsecSIAWorkspacesTargetSetsService) validateSecretExists(secretID string) error {
	// Create VM secrets service using the same authenticator
	secretsService, err := vmsecrets.NewIdsecSIASecretsVMService(s.ispAuth)
	if err != nil {
		return fmt.Errorf("failed to create secrets service for validation: %w", err)
	}

	// Try to retrieve the secret
	getSecret := &vmsecretsmodels.IdsecSIAVMGetSecret{
		SecretID: secretID,
	}
	_, err = secretsService.Secret(getSecret)
	if err != nil {
		return fmt.Errorf("secret '%s' does not exist in tenant - target set cannot be created with invalid secret reference", secretID)
	}

	return nil
}

// AddTargetSet adds a new target set with related strong account.
func (s *IdsecSIAWorkspacesTargetSetsService) AddTargetSet(addTargetSet *targetsetsmodels.IdsecSIAAddTargetSet) (*targetsetsmodels.IdsecSIATargetSet, error) {
	s.Logger.Info("Adding target set [%s]", addTargetSet.Name)

	// Validate that the secret exists before creating the target set
	// This matches UI behavior and prevents invalid configurations
	if addTargetSet.SecretID != "" {
		if err := s.validateSecretExists(addTargetSet.SecretID); err != nil {
			return nil, err
		}
	}

	var addTargetSetJSON map[string]interface{}
	err := mapstructure.Decode(addTargetSet, &addTargetSetJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Post(context.Background(), targetSetsURL, addTargetSetJSON)
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
		return nil, fmt.Errorf("failed to add target set - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	targetSetJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	targetSetJSONMap := targetSetJSON.(map[string]interface{})
	if name, ok := targetSetJSONMap["target_set"].(map[string]interface{})["name"]; ok {
		targetSetJSONMap["target_set"].(map[string]interface{})["id"] = name
	}
	var targetSet targetsetsmodels.IdsecSIATargetSet
	err = mapstructure.Decode(targetSetJSONMap["target_set"], &targetSet)
	if err != nil {
		return nil, err
	}
	return &targetSet, nil
}

// BulkAddTargetSets adds multiple target sets with related strong account.
func (s *IdsecSIAWorkspacesTargetSetsService) BulkAddTargetSets(bulkAddTargetSets *targetsetsmodels.IdsecSIABulkAddTargetSets) (*targetsetsmodels.IdsecSIABulkTargetSetResponse, error) {
	s.Logger.Info("Bulk adding target set [%v]", bulkAddTargetSets)

	// Validate strong account ID and all secret IDs
	for _, mapping := range bulkAddTargetSets.TargetSetsMapping {
		// Validate strong_account_id exists
		if mapping.StrongAccountID == "" {
			return nil, fmt.Errorf("strong_account_id is required in mapping")
		}
		if err := s.validateSecretExists(mapping.StrongAccountID); err != nil {
			return nil, fmt.Errorf("validation failed for strong_account_id '%s': %w", mapping.StrongAccountID, err)
		}

		// Validate all secret_ids match strong_account_id and exist
		for _, targetSet := range mapping.TargetSets {
			if targetSet.SecretID == "" {
				return nil, fmt.Errorf("secret_id is required for target set '%s'", targetSet.Name)
			}
			if targetSet.SecretID != mapping.StrongAccountID {
				return nil, fmt.Errorf("secret_id '%s' for target set '%s' does not match strong_account_id '%s'", targetSet.SecretID, targetSet.Name, mapping.StrongAccountID)
			}
			if err := s.validateSecretExists(targetSet.SecretID); err != nil {
				return nil, fmt.Errorf("validation failed for target set '%s': %w", targetSet.Name, err)
			}
		}
	}

	var bulkAddTargetSetsJSON map[string]interface{}
	err := mapstructure.Decode(bulkAddTargetSets, &bulkAddTargetSetsJSON)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Post(context.Background(), bulkTargetSetsURL, bulkAddTargetSetsJSON)
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
		return nil, fmt.Errorf("failed to bulk add target set - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	bulkTargetSetRespJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var bulkTargetSetsResp targetsetsmodels.IdsecSIABulkTargetSetResponse
	err = mapstructure.Decode(bulkTargetSetRespJSON, &bulkTargetSetsResp)
	if err != nil {
		return nil, err
	}
	return &bulkTargetSetsResp, nil
}

// DeleteTargetSet deletes a target set.
func (s *IdsecSIAWorkspacesTargetSetsService) DeleteTargetSet(deleteTargetSet *targetsetsmodels.IdsecSIADeleteTargetSet) error {
	s.Logger.Info("Deleting target set [%s]", deleteTargetSet.ID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(targetSetURL, deleteTargetSet.ID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete target set - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// BulkDeleteTargetSets deletes multiple target sets.
func (s *IdsecSIAWorkspacesTargetSetsService) BulkDeleteTargetSets(bulkDeleteTargetSets *targetsetsmodels.IdsecSIABulkDeleteTargetSets) (*targetsetsmodels.IdsecSIABulkTargetSetResponse, error) {

	s.Logger.Info("Bulk deleting target set [%v]", bulkDeleteTargetSets)
	// Trim whitespace from each name
	trimmedNames := make([]string, 0, len(bulkDeleteTargetSets.TargetSets))
	for _, name := range bulkDeleteTargetSets.TargetSets {
		trimmedNames = append(trimmedNames, strings.TrimSpace(name))
	}

	// Get all existing target sets
	allTargetSets, err := s.ListTargetSets()
	if err != nil {
		return nil, fmt.Errorf("failed to list target sets for bulk delete validation: %w", err)
	}
	existing := make(map[string]struct{})
	for _, ts := range allTargetSets {
		existing[strings.TrimSpace(ts.Name)] = struct{}{}
	}

	// Find missing target sets
	missing := make([]string, 0)
	toDelete := make([]string, 0, len(trimmedNames))
	for _, name := range trimmedNames {
		if _, found := existing[name]; found {
			toDelete = append(toDelete, name)
		} else {
			missing = append(missing, name)
		}
	}

	// If any are missing, return error and do not delete
	if len(missing) > 0 {
		return nil, fmt.Errorf("the following target sets do not exist: %v", missing)
	}

	// Only delete existing target sets
	if len(toDelete) > 0 {
		_, err := s.client.Delete(context.Background(), bulkTargetSetsURL, toDelete, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to bulk delete target sets: %w", err)
		}
	}

	// All requested target sets were deleted
	results := make([]targetsetsmodels.IdsecSIABulkTargetSetItemResult, 0, len(toDelete))
	for _, name := range toDelete {
		results = append(results, targetsetsmodels.IdsecSIABulkTargetSetItemResult{
			TargetSetName: name,
			Success:       true,
		})
	}
	resp := &targetsetsmodels.IdsecSIABulkTargetSetResponse{
		Results: results,
	}
	return resp, nil
}

// UpdateTargetSet updates a target set.
func (s *IdsecSIAWorkspacesTargetSetsService) UpdateTargetSet(updateTargetSet *targetsetsmodels.IdsecSIAUpdateTargetSet) (*targetsetsmodels.IdsecSIATargetSet, error) {
	s.Logger.Info("Updating target set [%s]", updateTargetSet.ID)

	// Convert struct to map, then remove empty values and the ID field
	var updateTargetSetJSON map[string]interface{}
	err := mapstructure.Decode(updateTargetSet, &updateTargetSetJSON)
	if err != nil {
		return nil, err
	}

	// Remove ID field and filter out empty string values
	delete(updateTargetSetJSON, "id")
	for key, value := range updateTargetSetJSON {
		if strValue, ok := value.(string); ok && strValue == "" {
			delete(updateTargetSetJSON, key)
		}
	}

	s.Logger.Info("Update payload being sent: %+v", updateTargetSetJSON)
	response, err := s.client.Put(context.Background(), fmt.Sprintf(targetSetURL, updateTargetSet.ID), updateTargetSetJSON)
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
		return nil, fmt.Errorf("failed to update target set - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	targetSetJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	targetSetJSONMap := targetSetJSON.(map[string]interface{})
	if name, ok := targetSetJSONMap["target_set"].(map[string]interface{})["name"]; ok {
		targetSetJSONMap["target_set"].(map[string]interface{})["id"] = name
	}
	var targetSet targetsetsmodels.IdsecSIATargetSet
	err = mapstructure.Decode(targetSetJSONMap["target_set"], &targetSet)
	if err != nil {
		return nil, err
	}
	return &targetSet, nil
}

// ListTargetSets lists all target sets.
func (s *IdsecSIAWorkspacesTargetSetsService) ListTargetSets() ([]*targetsetsmodels.IdsecSIATargetSet, error) {
	s.Logger.Info("Listing all target sets")
	response, err := s.ListTargetSetsWithOptions(nil)
	if err != nil {
		return nil, err
	}
	return response.TargetSets, nil
}

// ListTargetSetsWithOptions lists target sets with optional filtering.
func (s *IdsecSIAWorkspacesTargetSetsService) ListTargetSetsWithOptions(options *targetsetsmodels.IdsecSIAListTargetSetsOptions) (*targetsetsmodels.IdsecSIAListTargetSetsResponse, error) {
	s.Logger.Info("Listing target sets with options [%v]", options)

	// Build query parameters from options
	queryParams := make(map[string]string)
	if options != nil {
		if options.B64StartKey != nil && *options.B64StartKey != "" {
			queryParams["b64StartKey"] = *options.B64StartKey
		}
		if options.Name != nil && *options.Name != "" {
			queryParams["name"] = *options.Name
		}
		if options.StrongAccountID != nil && *options.StrongAccountID != "" {
			queryParams["strongAccountId"] = *options.StrongAccountID
		}
	}

	response, err := s.client.Get(context.Background(), targetSetsURL, queryParams)
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
		return nil, fmt.Errorf("failed to list target sets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	targetSetsResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	targetSetsResponseJSONMap := targetSetsResponseJSON.(map[string]interface{})

	// Add ID field to each target set (matches name)
	if targetSetsArray, ok := targetSetsResponseJSONMap["target_sets"].([]interface{}); ok {
		for _, targetSetMap := range targetSetsArray {
			if name, ok := targetSetMap.(map[string]interface{})["name"]; ok {
				targetSetMap.(map[string]interface{})["id"] = name
			}
		}
	}

	var listResponse targetsetsmodels.IdsecSIAListTargetSetsResponse
	err = mapstructure.Decode(targetSetsResponseJSONMap, &listResponse)
	if err != nil {
		return nil, err
	}
	return &listResponse, nil
}

// ListTargetSetsBy filters target sets by the provided filter.
func (s *IdsecSIAWorkspacesTargetSetsService) ListTargetSetsBy(targetSetsFilter *targetsetsmodels.IdsecSIATargetSetsFilter) ([]*targetsetsmodels.IdsecSIATargetSet, error) {
	s.Logger.Info("Listing target sets by filter [%v]", targetSetsFilter)
	targetSets, err := s.ListTargetSets()
	if err != nil {
		return nil, err
	}
	if targetSetsFilter.Name != "" {
		var filteredTargetSets []*targetsetsmodels.IdsecSIATargetSet
		for _, targetSet := range targetSets {
			if match, err := regexp.MatchString(targetSetsFilter.Name, targetSet.Name); err == nil && match {
				filteredTargetSets = append(filteredTargetSets, targetSet)
			}
		}
		targetSets = filteredTargetSets
	}
	if targetSetsFilter.SecretType != "" {
		var filteredTargetSets []*targetsetsmodels.IdsecSIATargetSet
		for _, targetSet := range targetSets {
			if match, err := regexp.MatchString(targetSetsFilter.SecretType, targetSet.SecretType); err == nil && match {
				filteredTargetSets = append(filteredTargetSets, targetSet)
			}
		}
		targetSets = filteredTargetSets
	}
	return targetSets, nil
}

// TargetSet retrieves a target set by name.
func (s *IdsecSIAWorkspacesTargetSetsService) TargetSet(getTargetSet *targetsetsmodels.IdsecSIAGetTargetSet) (*targetsetsmodels.IdsecSIATargetSet, error) {
	s.Logger.Info("Getting target set [%s]", getTargetSet.ID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(targetSetURL, getTargetSet.ID), nil)
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
		return nil, fmt.Errorf("failed to get target set - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	targetSetJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	targetSetJSONMap := targetSetJSON.(map[string]interface{})
	if name, ok := targetSetJSONMap["target_set"].(map[string]interface{})["name"]; ok {
		targetSetJSONMap["target_set"].(map[string]interface{})["id"] = name
	}
	var targetSet targetsetsmodels.IdsecSIATargetSet
	err = mapstructure.Decode(targetSetJSONMap["target_set"], &targetSet)
	if err != nil {
		return nil, err
	}
	return &targetSet, nil
}

// BulkTargetSets retrieves multiple target sets by their ids in a single API call.
func (s *IdsecSIAWorkspacesTargetSetsService) BulkTargetSets(getTargetSets *targetsetsmodels.IdsecSIAGetTargetSets) (*targetsetsmodels.IdsecSIAListTargetSetsResponse, error) {
	s.Logger.Info("Getting multiple target sets by ids [%v]", getTargetSets.IDList)

	// Build base64-encoded JSON array for path parameter
	// Trim whitespace from each name
	trimmedIDs := make([]string, 0, len(getTargetSets.IDList))
	for _, id := range getTargetSets.IDList {
		trimmedIDs = append(trimmedIDs, strings.TrimSpace(id))
	}
	jsonBytes, err := json.Marshal(trimmedIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal target set IDs to JSON: %w", err)
	}
	base64String := base64.URLEncoding.EncodeToString(jsonBytes)
	quotedBase64 := "'" + base64String + "'"
	apiURL := fmt.Sprintf(targetSetsGetMultipleURL, quotedBase64)

	response, err := s.client.Get(context.Background(), apiURL, nil)
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
		return nil, fmt.Errorf("failed to get multiple target sets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	targetSetsResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	targetSetsResponseJSONMap := targetSetsResponseJSON.(map[string]interface{})

	// Add ID field to each target set (matches name)
	foundIDs := make(map[string]struct{})
	if targetSetsArray, ok := targetSetsResponseJSONMap["target_sets"].([]interface{}); ok {
		for _, targetSetMap := range targetSetsArray {
			if name, ok := targetSetMap.(map[string]interface{})["name"]; ok {
				targetSetMap.(map[string]interface{})["id"] = name
				foundIDs[strings.TrimSpace(fmt.Sprintf("%v", name))] = struct{}{}
			}
		}
	}

	var listResponse targetsetsmodels.IdsecSIAListTargetSetsResponse
	err = mapstructure.Decode(targetSetsResponseJSONMap, &listResponse)
	if err != nil {
		return nil, err
	}

	// Detect missing IDs
	missingIDs := []string{}
	for _, requestedID := range getTargetSets.IDList {
		trimmedID := strings.TrimSpace(requestedID)
		if _, found := foundIDs[trimmedID]; !found {
			missingIDs = append(missingIDs, trimmedID)
		}
	}

	if len(missingIDs) > 0 {
		return &listResponse, fmt.Errorf("the following target sets do not exist: %v", missingIDs)
	}

	return &listResponse, nil
}

// TargetSetsCount retrieves the count of target sets with optional filtering.
func (s *IdsecSIAWorkspacesTargetSetsService) TargetSetsCount(options *targetsetsmodels.IdsecSIATargetSetsCountOptions) (*targetsetsmodels.IdsecSIATargetSetsCountResponse, error) {
	s.Logger.Info("Getting target sets count with options [%v]", options)

	// Build query parameters from options
	queryParams := make(map[string]string)
	if options != nil {
		if options.B64StartKey != nil && *options.B64StartKey != "" {
			queryParams["b64StartKey"] = *options.B64StartKey
		}
		if options.Name != nil && *options.Name != "" {
			queryParams["name"] = *options.Name
		}
		if options.StrongAccountID != nil && *options.StrongAccountID != "" {
			queryParams["strongAccountId"] = *options.StrongAccountID
		}
	}

	response, err := s.client.Get(context.Background(), targetSetsCountURL, queryParams)
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
		return nil, fmt.Errorf("failed to get target sets count - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	countResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var countResponse targetsetsmodels.IdsecSIATargetSetsCountResponse
	err = mapstructure.Decode(countResponseJSON, &countResponse)
	if err != nil {
		return nil, err
	}

	return &countResponse, nil
}

// TargetSetsStats retrieves statistics about target sets.
func (s *IdsecSIAWorkspacesTargetSetsService) TargetSetsStats() (*targetsetsmodels.IdsecSIATargetSetsStats, error) {
	targetSets, err := s.ListTargetSets()
	if err != nil {
		return nil, err
	}
	var targetSetsStats targetsetsmodels.IdsecSIATargetSetsStats
	targetSetsStats.TargetSetsCount = len(targetSets)
	targetSetsStats.TargetSetsCountPerSecretType = make(map[string]int)
	for _, targetSet := range targetSets {
		if _, ok := targetSetsStats.TargetSetsCountPerSecretType[targetSet.SecretType]; !ok {
			targetSetsStats.TargetSetsCountPerSecretType[targetSet.SecretType] = 0
		}
		targetSetsStats.TargetSetsCountPerSecretType[targetSet.SecretType]++
	}
	return &targetSetsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSIAWorkspacesTargetSetsService.
func (s *IdsecSIAWorkspacesTargetSetsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
