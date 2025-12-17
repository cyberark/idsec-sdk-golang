package db

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
)

const (
	resourcesURL    = "/api/adb/resources"
	resourceURL     = "/api/adb/resources/%d"
	dbTargetsURL    = "/api/database-targets"
	dbTargetByIDURL = "/api/database-targets/%s"
)

// IdsecSIAWorkspacesDBService is the service for managing databases in a workspace.
type IdsecSIAWorkspacesDBService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSIAWorkspacesDBService creates a new instance of IdsecSIAWorkspacesDBService.
func NewIdsecSIAWorkspacesDBService(authenticators ...auth.IdsecAuth) (*IdsecSIAWorkspacesDBService, error) {
	dbService := &IdsecSIAWorkspacesDBService{}
	var dbServiceInterface services.IdsecService = dbService
	baseService, err := services.NewIdsecBaseService(dbServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", dbService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	dbService.client = client
	dbService.ispAuth = ispAuth
	dbService.IdsecBaseService = baseService
	return dbService, nil
}

func (s *IdsecSIAWorkspacesDBService) parseDatabaseTagsIntoMap(databaseJSONMap map[string]interface{}) {
	if tags, ok := databaseJSONMap["tags"].([]interface{}); ok {
		parsedTags := make(map[string]string)
		for _, tag := range tags {
			if tagMap, ok := tag.(map[string]interface{}); ok {
				key, keyOk := tagMap["key"].(string)
				value, valueOk := tagMap["value"].(string)
				if keyOk && valueOk {
					parsedTags[key] = value
				}
			}
		}
		databaseJSONMap["tags"] = parsedTags
	}
}

func (s *IdsecSIAWorkspacesDBService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIAWorkspacesDBService) listDatabasesWithFilters(providerFamily string, tags []workspacesdbmodels.IdsecSIADBTag) (*workspacesdbmodels.IdsecSIADBDatabaseInfoList, error) {
	params := make(map[string]string)
	if providerFamily != "" {
		params["provider-family"] = providerFamily
	}
	for _, tag := range tags {
		params[fmt.Sprintf("key.%s", tag.Key)] = tag.Value
	}
	response, err := s.client.Get(context.Background(), resourcesURL, params)
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
		return nil, fmt.Errorf("failed to list databases with filters - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	databasesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var databases workspacesdbmodels.IdsecSIADBDatabaseInfoList
	err = mapstructure.Decode(databasesJSON, &databases)
	if err != nil {
		return nil, err
	}
	return &databases, nil
}

// AddDatabase adds a new database to the SIA workspace.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use AddDatabaseTarget instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) AddDatabase(addDatabase *workspacesdbmodels.IdsecSIADBAddDatabase) (*workspacesdbmodels.IdsecSIADBDatabase, error) {
	s.Logger.Info("Adding database [%s]", addDatabase.Name)
	s.Logger.Warning("The function AddDatabase that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	// Validate ProviderEngine
	if !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, addDatabase.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", addDatabase.ProviderEngine)
	}
	// Set default port if not provided
	if addDatabase.Port == 0 {
		family, ok := workspacesdbmodels.DatabasesEnginesToFamily[addDatabase.ProviderEngine]
		if !ok {
			return nil, fmt.Errorf("unknown provider engine: %s", addDatabase.ProviderEngine)
		}
		addDatabase.Port = workspacesdbmodels.DatabaseFamiliesDefaultPorts[family]
	}
	if addDatabase.Services == nil {
		addDatabase.Services = []string{}
	}
	var addDatabaseJSON map[string]interface{}
	err := mapstructure.Decode(addDatabase, &addDatabaseJSON)
	if err != nil {
		return nil, err
	}
	if addDatabase.Tags != nil {
		addDatabaseJSON["tags"] = make([]workspacesdbmodels.IdsecSIADBTag, len(addDatabase.Tags))
		idx := 0
		for key, value := range addDatabase.Tags {
			if key == "" {
				continue
			}
			addDatabaseJSON["tags"].([]workspacesdbmodels.IdsecSIADBTag)[idx] = workspacesdbmodels.IdsecSIADBTag{
				Key:   key,
				Value: value,
			}
			idx++
		}
	}
	response, err := s.client.Post(context.Background(), resourcesURL, addDatabaseJSON)
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
		return nil, fmt.Errorf("failed to database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	databaseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	databaseJSONMap := databaseJSON.(map[string]interface{})
	databaseID, ok := databaseJSONMap["target_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing target_id in response")
	}
	getDatabase := &workspacesdbmodels.IdsecSIADBGetDatabase{ID: int(databaseID)}
	return s.Database(getDatabase)
}

// DeleteDatabase deletes a database.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use DeleteDatabaseTarget instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) DeleteDatabase(deleteDatabase *workspacesdbmodels.IdsecSIADBDeleteDatabase) error {
	s.Logger.Warning("The function DeleteDatabase that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	if deleteDatabase.Name != "" && deleteDatabase.ID == 0 {
		databases, err := s.ListDatabasesBy(&workspacesdbmodels.IdsecSIADBDatabasesFilter{Name: deleteDatabase.Name})
		if err != nil {
			return fmt.Errorf("failed to fetch database ID by name: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return fmt.Errorf("no database found with name: %s", deleteDatabase.Name)
		}
		deleteDatabase.ID = databases.Items[0].ID
	}
	s.Logger.Info("Deleting database [%d]", deleteDatabase.ID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(resourceURL, deleteDatabase.ID), nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete database: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			s.Logger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	return nil
}

// UpdateDatabase updates a database.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use UpdateDatabaseTarget instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) UpdateDatabase(updateDatabase *workspacesdbmodels.IdsecSIADBUpdateDatabase) (*workspacesdbmodels.IdsecSIADBDatabase, error) {
	s.Logger.Warning("The function UpdateDatabase that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	if updateDatabase.Name != "" && updateDatabase.ID == 0 {
		databases, err := s.ListDatabasesBy(&workspacesdbmodels.IdsecSIADBDatabasesFilter{Name: updateDatabase.Name})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch database ID by name: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return nil, fmt.Errorf("failed to update database - name [%s] not found", updateDatabase.Name)
		}
		updateDatabase.ID = databases.Items[0].ID
	}
	// Validate ProviderEngine
	if updateDatabase.ProviderEngine != "" && !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, updateDatabase.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", updateDatabase.ProviderEngine)
	}
	existingDatabase, err := s.Database(&workspacesdbmodels.IdsecSIADBGetDatabase{ID: updateDatabase.ID, Name: updateDatabase.Name})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve existing database: %w", err)
	}

	// Merge the existing database details with the update request
	mergedDatabase := make(map[string]interface{})
	existingDatabaseMap := make(map[string]interface{})
	updateDatabaseMap := make(map[string]interface{})

	// As update database it PUT, we need first to fetch the existing database,
	// and merge the update params with the existing database, so that all fields will be sent.
	if err := mapstructure.Decode(existingDatabase, &existingDatabaseMap); err != nil {
		return nil, fmt.Errorf("failed to decode existing database: %w", err)
	}
	if err := mapstructure.Decode(updateDatabase, &updateDatabaseMap); err != nil {
		return nil, fmt.Errorf("failed to decode update database payload: %w", err)
	}
	// Merge the maps
	for key, value := range existingDatabaseMap {
		mergedDatabase[key] = value
	}
	for key, value := range updateDatabaseMap {
		mergedDatabase[key] = value
	}

	// Remove unnecessary fields and handle renaming
	delete(mergedDatabase, "name")
	delete(mergedDatabase, "new_name")
	if updateDatabase.NewName != "" {
		mergedDatabase["name"] = updateDatabase.NewName
	} else if updateDatabase.Name != "" {
		mergedDatabase["name"] = updateDatabase.Name
	} else {
		mergedDatabase["name"] = existingDatabase.Name
	}

	// Handling configured auth method
	delete(mergedDatabase, "configured_auth_method")
	if updateDatabase.ConfiguredAuthMethodType == "" {
		mergedDatabase["configured_auth_method_type"] = existingDatabase.ConfiguredAuthMethod.DatabaseAuthMethod.AuthMethod.AuthMethodType
	}

	// Handling provider engine
	delete(mergedDatabase, "provider_details")
	if updateDatabase.ProviderEngine == "" {
		mergedDatabase["provider_engine"] = existingDatabase.ProviderDetails.Engine
	}

	if updateDatabase.Tags != nil {
		mergedDatabase["tags"] = make([]workspacesdbmodels.IdsecSIADBTag, len(updateDatabase.Tags))
		idx := 0
		for key, value := range updateDatabase.Tags {
			if key == "" {
				continue
			}
			mergedDatabase["tags"].([]workspacesdbmodels.IdsecSIADBTag)[idx] = workspacesdbmodels.IdsecSIADBTag{
				Key:   key,
				Value: value,
			}
			idx++
		}
	}

	s.Logger.Info("Updating database [%d]", updateDatabase.ID)
	response, err := s.client.Put(context.Background(), fmt.Sprintf(resourceURL, updateDatabase.ID), mergedDatabase)
	if err != nil {
		return nil, fmt.Errorf("failed to update database: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			s.Logger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.Database(&workspacesdbmodels.IdsecSIADBGetDatabase{ID: updateDatabase.ID})
}

// Database retrieves a database by id or name.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use DatabaseTarget instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) Database(getDatabase *workspacesdbmodels.IdsecSIADBGetDatabase) (*workspacesdbmodels.IdsecSIADBDatabase, error) {
	s.Logger.Warning("The function Database that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	// If Name is provided but ID is not, fetch the ID by filtering databases
	if getDatabase.Name != "" && getDatabase.ID == 0 {
		filter := &workspacesdbmodels.IdsecSIADBDatabasesFilter{Name: getDatabase.Name}
		databases, err := s.ListDatabasesBy(filter)
		if err != nil {
			return nil, fmt.Errorf("failed to list databases: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return nil, fmt.Errorf("failed to get database - name [%s] not found", getDatabase.Name)
		}
		getDatabase.ID = databases.Items[0].ID
	}
	s.Logger.Info("Getting database [%d]", getDatabase.ID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(resourceURL, getDatabase.ID), nil)
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
		return nil, fmt.Errorf("failed to get database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	databaseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	databaseJSONMap := databaseJSON.(map[string]interface{})
	s.parseDatabaseTagsIntoMap(databaseJSONMap)
	var database workspacesdbmodels.IdsecSIADBDatabase
	err = mapstructure.Decode(databaseJSONMap, &database)
	if err != nil {
		return nil, err
	}
	return &database, nil
}

// ListDatabases lists all databases.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use ListDatabaseTargets instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) ListDatabases() (*workspacesdbmodels.IdsecSIADBDatabaseInfoList, error) {
	s.Logger.Info("Listing all databases")
	s.Logger.Warning("The function ListDatabases that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	return s.listDatabasesWithFilters("", nil)
}

// ListDatabasesBy filters databases by the given filters.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use ListDatabaseTargetsBy instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) ListDatabasesBy(databasesFilter *workspacesdbmodels.IdsecSIADBDatabasesFilter) (*workspacesdbmodels.IdsecSIADBDatabaseInfoList, error) {
	s.Logger.Warning("The function ListDatabasesBy that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	if databasesFilter.ProviderEngine != "" && !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, databasesFilter.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", databasesFilter.ProviderEngine)
	}
	s.Logger.Info("Listing databases by filters [%+v]", databasesFilter)
	databases, err := s.listDatabasesWithFilters(databasesFilter.ProviderFamily, databasesFilter.Tags)
	if err != nil {
		return nil, fmt.Errorf("failed to list databases with filters: %w", err)
	}
	var filteredItems []workspacesdbmodels.IdsecSIADBDatabaseInfo
	for _, database := range databases.Items {
		if databasesFilter.Name != "" {
			matched, err := regexp.MatchString(databasesFilter.Name, database.Name)
			if err != nil || !matched {
				continue
			}
		}
		if databasesFilter.ProviderEngine != "" && database.ProviderInfo.Engine != databasesFilter.ProviderEngine {
			continue
		}
		if databasesFilter.ProviderFamily != "" && database.ProviderInfo.Family != databasesFilter.ProviderFamily {
			continue
		}
		if databasesFilter.ProviderWorkspace != "" && database.ProviderInfo.Workspace != databasesFilter.ProviderWorkspace {
			continue
		}
		if len(databasesFilter.AuthMethods) > 0 {
			matchesAuthMethod := false
			for _, authMethod := range databasesFilter.AuthMethods {
				if database.ConfiguredAuthMethodType == authMethod {
					matchesAuthMethod = true
					break
				}
			}
			if !matchesAuthMethod {
				continue
			}
		}
		if databasesFilter.DBWarningsFilter != "" {
			if (databasesFilter.DBWarningsFilter == workspacesdbmodels.AnyError || databasesFilter.DBWarningsFilter == workspacesdbmodels.NoCertificates) && database.Certificate == "" {
				continue
			}
			if (databasesFilter.DBWarningsFilter == workspacesdbmodels.AnyError || databasesFilter.DBWarningsFilter == workspacesdbmodels.NoSecrets) && database.SecretID == "" {
				continue
			}
		}
		// Add to filtered items if all conditions are met
		filteredItems = append(filteredItems, database)
	}
	databases.Items = filteredItems
	databases.TotalCount = len(filteredItems)
	return databases, nil
}

// DatabasesStats calculates statistics about databases.
//
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  Use DatabaseTargetsStats instead. This method uses the legacy API which will be removed in a future version.
func (s *IdsecSIAWorkspacesDBService) DatabasesStats() (*workspacesdbmodels.IdsecSIADBDatabasesStats, error) {
	s.Logger.Info("Calculating databases stats")
	s.Logger.Warning("The function DatabasesStats that is being used is deprecated and will be removed in a future version. Please use AddDatabaseTarget instead.")
	databases, err := s.ListDatabases()
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}
	// Initialize the stats object
	databasesStats := &workspacesdbmodels.IdsecSIADBDatabasesStats{
		DatabasesCount:             len(databases.Items),
		DatabasesCountByEngine:     make(map[string]int),
		DatabasesCountByWorkspace:  make(map[string]int),
		DatabasesCountByFamily:     make(map[string]int),
		DatabasesCountByAuthMethod: make(map[string]int),
		DatabasesCountByWarning:    make(map[string]int),
	}
	// Calculate databases per engine
	for _, database := range databases.Items {
		engine := database.ProviderInfo.Engine
		databasesStats.DatabasesCountByEngine[engine]++
	}
	// Calculate databases per workspace
	for _, database := range databases.Items {
		workspace := database.ProviderInfo.Workspace
		databasesStats.DatabasesCountByWorkspace[workspace]++
	}
	// Calculate databases per family
	for _, database := range databases.Items {
		family := database.ProviderInfo.Family
		databasesStats.DatabasesCountByFamily[family]++
	}
	// Calculate databases per auth method
	for _, database := range databases.Items {
		authMethod := database.ConfiguredAuthMethodType
		databasesStats.DatabasesCountByAuthMethod[authMethod]++
	}
	// Calculate databases per warning
	for _, database := range databases.Items {
		if database.Certificate == "" {
			databasesStats.DatabasesCountByWarning[workspacesdbmodels.NoCertificates]++
		}
		if database.SecretID == "" {
			databasesStats.DatabasesCountByWarning[workspacesdbmodels.NoSecrets]++
		}
	}
	return databasesStats, nil
}

// ListEngineTypes returns all possible database engine types.
func (s *IdsecSIAWorkspacesDBService) ListEngineTypes() []string {
	return workspacesdbmodels.DatabaseEngineTypes
}

// ListFamilyTypes returns all possible database family types.
func (s *IdsecSIAWorkspacesDBService) ListFamilyTypes() []string {
	return workspacesdbmodels.DatabaseFamilyTypes
}

// ServiceConfig returns the service configuration for the IdsecSIATargetSetsWorkspaceService.
func (s *IdsecSIAWorkspacesDBService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// AddDatabaseTarget adds a new database to the SIA workspace using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) AddDatabaseTarget(addDatabase *workspacesdbmodels.IdsecSIADBAddDatabaseTarget) (*workspacesdbmodels.IdsecSIADBDatabaseTarget, error) {
	s.Logger.Info("Adding database [%s]", addDatabase.Name)
	// Validate ProviderEngine
	if !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, addDatabase.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", addDatabase.ProviderEngine)
	}
	// Set default port if not provided
	if addDatabase.Port == 0 {
		family, ok := workspacesdbmodels.DatabasesEnginesToFamily[addDatabase.ProviderEngine]
		if !ok {
			return nil, fmt.Errorf("unknown provider engine: %s", addDatabase.ProviderEngine)
		}
		addDatabase.Port = workspacesdbmodels.DatabaseFamiliesDefaultPorts[family]
	}
	if addDatabase.Services == nil {
		addDatabase.Services = []string{}
	}
	var addDatabaseJSON map[string]interface{}
	err := mapstructure.Decode(addDatabase, &addDatabaseJSON)
	if err != nil {
		return nil, err
	}

	addDatabaseJsonCamel, err := common.SerializeJSONCamel(addDatabaseJSON)
	if err != nil {
		return nil, err
	}

	response, err := s.client.Post(context.Background(), dbTargetsURL, addDatabaseJsonCamel)
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
		return nil, fmt.Errorf("failed to database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	databaseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	databaseJSONMap := databaseJSON.(map[string]interface{})
	databaseID, ok := databaseJSONMap["id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing targetID in response")
	}

	getDatabase := &workspacesdbmodels.IdsecSIADBGetDatabaseTarget{ID: databaseID}
	return s.DatabaseTarget(getDatabase)
}

// DeleteDatabaseTarget deletes a database using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) DeleteDatabaseTarget(deleteDatabase *workspacesdbmodels.IdsecSIADBDeleteDatabaseTarget) error {
	if deleteDatabase.Name != "" && deleteDatabase.ID == "" {
		databases, err := s.ListDatabaseTargetsBy(&workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{Name: deleteDatabase.Name})
		if err != nil {
			return fmt.Errorf("failed to fetch database ID by name: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return fmt.Errorf("no database found with name: %s", deleteDatabase.Name)
		}
		deleteDatabase.ID = databases.Items[0].ID
	}
	s.Logger.Info("Deleting database [%s]", deleteDatabase.ID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(dbTargetByIDURL, deleteDatabase.ID), nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete database: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			s.Logger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	return nil
}

// UpdateDatabaseTarget updates a database using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) UpdateDatabaseTarget(updateDatabase *workspacesdbmodels.IdsecSIADBUpdateDatabaseTarget) (*workspacesdbmodels.IdsecSIADBDatabaseTarget, error) {
	if updateDatabase.Name != "" && updateDatabase.ID == "" {
		databases, err := s.ListDatabaseTargetsBy(&workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{Name: updateDatabase.Name})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch database ID by name: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return nil, fmt.Errorf("failed to update database - name [%s] not found", updateDatabase.Name)
		}
		updateDatabase.ID = databases.Items[0].ID
	}
	// Validate ProviderEngine
	if updateDatabase.ProviderEngine != "" && !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, updateDatabase.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", updateDatabase.ProviderEngine)
	}
	existingDatabase, err := s.DatabaseTarget(&workspacesdbmodels.IdsecSIADBGetDatabaseTarget{ID: updateDatabase.ID, Name: updateDatabase.Name})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve existing database: %w", err)
	}

	// Merge the existing database details with the update request
	mergedDatabase := make(map[string]interface{})
	existingDatabaseMap := make(map[string]interface{})
	updateDatabaseMap := make(map[string]interface{})

	// As update database it PUT, we need first to fetch the existing database,
	// and merge the update params with the existing database, so that all fields will be sent.
	if err := mapstructure.Decode(existingDatabase, &existingDatabaseMap); err != nil {
		return nil, fmt.Errorf("failed to decode existing database: %w", err)
	}
	if err := mapstructure.Decode(updateDatabase, &updateDatabaseMap); err != nil {
		return nil, fmt.Errorf("failed to decode update database payload: %w", err)
	}
	// Merge the maps
	for key, value := range existingDatabaseMap {
		mergedDatabase[key] = value
	}
	for key, value := range updateDatabaseMap {
		mergedDatabase[key] = value
	}

	// Remove unnecessary fields and handle renaming
	delete(mergedDatabase, "name")
	delete(mergedDatabase, "new_name")
	if updateDatabase.NewName != "" {
		mergedDatabase["name"] = updateDatabase.NewName
	} else if updateDatabase.Name != "" {
		mergedDatabase["name"] = updateDatabase.Name
	} else {
		mergedDatabase["name"] = existingDatabase.Name
	}

	// Handling configured auth method
	if updateDatabase.ConfiguredAuthMethodType == "" {
		mergedDatabase["configured_auth_method_type"] = existingDatabase.ConfiguredAuthMethodType
	}

	// Handling provider engine
	if updateDatabase.ProviderEngine == "" {
		mergedDatabase["provider_engine"] = existingDatabase.ProviderEngine
	}

	// Remove database ID from payload
	updateDatabaseId := updateDatabase.ID
	delete(mergedDatabase, "id")

	s.Logger.Info("Updating database [%s]", updateDatabaseId)
	mergedDatabaseJsonCamel, err := common.SerializeJSONCamel(mergedDatabase)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Put(context.Background(), fmt.Sprintf(dbTargetByIDURL, updateDatabaseId), mergedDatabaseJsonCamel)
	if err != nil {
		return nil, fmt.Errorf("failed to update database: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			s.Logger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.DatabaseTarget(&workspacesdbmodels.IdsecSIADBGetDatabaseTarget{ID: updateDatabaseId})
}

// DatabaseTarget retrieves a database by id or name using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) DatabaseTarget(getDatabase *workspacesdbmodels.IdsecSIADBGetDatabaseTarget) (*workspacesdbmodels.IdsecSIADBDatabaseTarget, error) {
	if getDatabase.Name == "" && getDatabase.ID == "" {
		return nil, fmt.Errorf("either ID or Name must be provided to get a database target")
	}

	// If Name is provided but ID is not, fetch the ID by filtering databases
	if getDatabase.Name != "" && getDatabase.ID == "" {
		filter := &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{Name: getDatabase.Name}
		databases, err := s.ListDatabaseTargetsBy(filter)
		if err != nil {
			return nil, fmt.Errorf("failed to list databases: %w", err)
		}
		if len(databases.Items) == 0 || len(databases.Items) != 1 {
			return nil, fmt.Errorf("failed to get database - name [%s] not found", getDatabase.Name)
		}
		getDatabase.ID = databases.Items[0].ID
	}
	s.Logger.Info("Getting database [%s]", getDatabase.ID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(dbTargetByIDURL, getDatabase.ID), nil)
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
		return nil, fmt.Errorf("failed to get database - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	databaseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	databaseJSONMap := databaseJSON.(map[string]interface{})
	var database workspacesdbmodels.IdsecSIADBDatabaseTarget
	err = mapstructure.Decode(databaseJSONMap, &database)
	if err != nil {
		return nil, err
	}
	return &database, nil
}

// ListDatabaseTargets lists all databases using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) ListDatabaseTargets() (*workspacesdbmodels.IdsecSIADBDatabaseTargetInfoList, error) {
	s.Logger.Info("Listing all databases")
	return s.listDatabaseTargetsWithFilters("", 0, nil)
}

// ListDatabaseTargetsBy filters databases by the given filters using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) ListDatabaseTargetsBy(databasesFilter *workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter) (*workspacesdbmodels.IdsecSIADBDatabaseTargetInfoList, error) {
	if databasesFilter.ProviderEngine != "" && !slices.Contains(workspacesdbmodels.DatabaseEngineTypes, databasesFilter.ProviderEngine) {
		return nil, fmt.Errorf("invalid provider engine: %s", databasesFilter.ProviderEngine)
	}
	s.Logger.Info("Listing databases by filters [%+v]", databasesFilter)
	databases, err := s.listDatabaseTargetsWithFilters(databasesFilter.ProviderFamily, databasesFilter.Limit, &databasesFilter.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list databases with filters: %w", err)
	}
	var filteredItems []workspacesdbmodels.IdsecSIADBDatabaseTargetInfo
	for _, database := range databases.Items {
		if databasesFilter.Name != "" {
			matched, err := regexp.MatchString(databasesFilter.Name, database.Name)
			if err != nil || !matched {
				continue
			}
		}
		if databasesFilter.ProviderEngine != "" && database.ProviderEngine != databasesFilter.ProviderEngine {
			continue
		}
		if len(databasesFilter.AuthMethods) > 0 {
			matchesAuthMethod := false
			for _, authMethod := range databasesFilter.AuthMethods {
				if database.ConfiguredAuthMethodType == authMethod {
					matchesAuthMethod = true
					break
				}
			}
			if !matchesAuthMethod {
				continue
			}
		}
		if databasesFilter.DBWarningsFilter != "" {
			if (databasesFilter.DBWarningsFilter == workspacesdbmodels.AnyError || databasesFilter.DBWarningsFilter == workspacesdbmodels.NoCertificates) && database.Certificate == "" {
				continue
			}
			if (databasesFilter.DBWarningsFilter == workspacesdbmodels.AnyError || databasesFilter.DBWarningsFilter == workspacesdbmodels.NoSecrets) && database.SecretID == "" {
				continue
			}
		}
		// Add to filtered items if all conditions are met
		filteredItems = append(filteredItems, database)
	}
	databases.Items = filteredItems
	databases.TotalCount = len(filteredItems)
	return databases, nil
}

// DatabaseTargetsStats calculates statistics about databases using the database-onboarding new API
func (s *IdsecSIAWorkspacesDBService) DatabaseTargetsStats() (*workspacesdbmodels.IdsecSIADBDatabasesStats, error) {
	s.Logger.Info("Calculating databases stats")
	databases, err := s.ListDatabaseTargets()
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}
	// Initialize the stats object
	databasesStats := &workspacesdbmodels.IdsecSIADBDatabasesStats{
		DatabasesCount:             len(databases.Items),
		DatabasesCountByEngine:     make(map[string]int),
		DatabasesCountByWorkspace:  make(map[string]int),
		DatabasesCountByFamily:     make(map[string]int),
		DatabasesCountByAuthMethod: make(map[string]int),
		DatabasesCountByWarning:    make(map[string]int),
	}
	// Calculate databases per engine
	for _, database := range databases.Items {
		engine := database.ProviderEngine
		databasesStats.DatabasesCountByEngine[engine]++
	}
	// Calculate databases per platform
	for _, database := range databases.Items {
		platform := database.Platform
		databasesStats.DatabasesCountByWorkspace[platform]++
	}
	// Calculate databases per auth method
	for _, database := range databases.Items {
		authMethod := database.ConfiguredAuthMethodType
		databasesStats.DatabasesCountByAuthMethod[authMethod]++
	}
	// Calculate databases per warning
	for _, database := range databases.Items {
		if database.Certificate == "" {
			databasesStats.DatabasesCountByWarning[workspacesdbmodels.NoCertificates]++
		}
		if database.SecretID == "" {
			databasesStats.DatabasesCountByWarning[workspacesdbmodels.NoSecrets]++
		}
	}
	return databasesStats, nil
}

func (s *IdsecSIAWorkspacesDBService) listDatabaseTargetsWithFilters(providerFamily string, limit int, offset *int) (*workspacesdbmodels.IdsecSIADBDatabaseTargetInfoList, error) {
	params := make(map[string]string)
	if providerFamily != "" {
		params["provideFamily"] = providerFamily
	}
	if limit > 0 {
		params["limit"] = fmt.Sprintf("%d", limit)
	}
	if offset != nil {
		params["offset"] = fmt.Sprintf("%d", *offset)
	}
	response, err := s.client.Get(context.Background(), dbTargetsURL, params)
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
		return nil, fmt.Errorf("failed to list databases with filters - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	databasesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var databases workspacesdbmodels.IdsecSIADBDatabaseTargetInfoList
	err = mapstructure.Decode(databasesJSON, &databases)
	if err != nil {
		return nil, err
	}
	return &databases, nil
}
