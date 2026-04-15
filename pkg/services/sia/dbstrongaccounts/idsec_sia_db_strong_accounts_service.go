package dbstrongaccounts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	dbstrongaccountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/dbstrongaccounts/models"
)

const (
	strongAccountsURL = "/api/database-strong-accounts"
	strongAccountURL  = "/api/database-strong-accounts/%s"
)

// Platform constants for strong accounts
const (
	PlatformPostgreSQL    = "PostgreSQL"
	PlatformMySQL         = "MySQL"
	PlatformMariaDB       = "MariaDB"
	PlatformMSSql         = "MSSql"
	PlatformOracle        = "Oracle"
	PlatformMongoDB       = "MongoDB"
	PlatformDB2UnixSSH    = "DB2UnixSSH"
	PlatformDomainAccount = "WinDomain"
	PlatformAWSAccessKeys = "AWSAccessKeys"
)

// IdsecSIADBStrongAccountPage is a page of IdsecSIADBStrongAccount items.
type IdsecSIADBStrongAccountPage = common.IdsecPage[dbstrongaccountsmodels.IdsecSIADBStrongAccount]

const (
	defaultLimit = 500
	minLimit     = 1
	maxLimit     = 1000
)

var (
	// platformToRequiredAccountProperties maps each platform to its required account properties.
	platformToRequiredAccountProperties = map[string][]string{
		PlatformPostgreSQL:    {"username"},
		PlatformMySQL:         {"username"},
		PlatformMariaDB:       {"username"},
		PlatformMSSql:         {"username"},
		PlatformOracle:        {"username"},
		PlatformMongoDB:       {"username", "address", "database"},
		PlatformDB2UnixSSH:    {"username", "address"},
		PlatformDomainAccount: {"username", "address"},
		PlatformAWSAccessKeys: {"username", "aws_access_key_id", "aws_account_id"},
	}

	// platformToOptionalAccountProperties maps each platform to its optional account properties.
	platformToOptionalAccountProperties = map[string][]string{
		PlatformPostgreSQL:    {"port", "database", "dsn", "address"},
		PlatformMySQL:         {"port", "database", "dsn", "address"},
		PlatformMariaDB:       {"port", "database", "dsn", "address"},
		PlatformMSSql:         {"port", "database", "dsn", "address", "reconcile_is_win_account"},
		PlatformOracle:        {"port", "database", "dsn", "address"},
		PlatformMongoDB:       {"port", "auth_database", "dsn", "replica_set", "use_ssl"},
		PlatformDB2UnixSSH:    {},
		PlatformDomainAccount: {},
		PlatformAWSAccessKeys: {},
	}

	platformToRequiredSecretPasswordObjectProperties = map[string][]string{
		PlatformPostgreSQL:    {"password"},
		PlatformMySQL:         {"password"},
		PlatformMariaDB:       {"password"},
		PlatformMSSql:         {"password"},
		PlatformOracle:        {"password"},
		PlatformMongoDB:       {"password"},
		PlatformDB2UnixSSH:    {"password"},
		PlatformDomainAccount: {"password"},
		PlatformAWSAccessKeys: {"secret_access_key"},
	}

	// pamRequiredProperties lists required properties for PAM accounts.
	pamRequiredProperties = []string{"safe", "account_name"}
)

// IdsecSIADBStrongAccountsService is the service for managing db strong accounts.
type IdsecSIADBStrongAccountsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSIADBStrongAccountsService creates a new instance of IdsecSIADBStrongAccountsService.
func NewIdsecSIADBStrongAccountsService(authenticators ...auth.IdsecAuth) (*IdsecSIADBStrongAccountsService, error) {
	strongAccountsService := &IdsecSIADBStrongAccountsService{}
	var strongAccountsServiceInterface services.IdsecService = strongAccountsService
	baseService, err := services.NewIdsecBaseService(strongAccountsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", strongAccountsService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	strongAccountsService.IdsecBaseService = baseService
	strongAccountsService.IdsecISPBaseService = ispBaseService
	return strongAccountsService, nil
}

func (s *IdsecSIADBStrongAccountsService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// ServiceConfig returns the service configuration for the IdsecSIADBStrongAccountsService.
func (s *IdsecSIADBStrongAccountsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

func hasValue(value interface{}) bool {
	if value == nil {
		return false
	}
	if valueString, ok := value.(string); ok {
		return valueString != ""
	}
	if valueInt, ok := value.(int); ok {
		return valueInt != 0
	}
	return true
}

// validateManagedAccountUpdateFields validates that all required fields for managed accounts are provided in the update request.
func validateManagedAccountUpdateFields(updateAccountModel map[string]interface{}) error {
	platform, ok := updateAccountModel["platform"].(string)
	if !ok || platform == "" {
		return fmt.Errorf("platform is required for managed accounts (all required fields must be provided in update request)")
	}
	requiredFields, ok := platformToRequiredAccountProperties[platform]
	if !ok {
		return fmt.Errorf("unsupported platform: %s", platform)
	}
	for _, field := range requiredFields {
		if value, ok := updateAccountModel[field]; !ok || !hasValue(value) {
			return fmt.Errorf("%s is required for platform %s (all required fields must be provided in update request)", field, platform)
		}
	}
	return nil
}

// validatePamAccountUpdateFields validates that all required fields for PAM accounts are provided in the update request.
func validatePamAccountUpdateFields(updateAccountModel map[string]interface{}) error {
	for _, field := range pamRequiredProperties {
		if value, ok := updateAccountModel[field]; !ok || !hasValue(value) {
			return fmt.Errorf("%s is required for PAM accounts (all required fields must be provided in update request)", field)
		}
	}
	return nil
}

// serializePamAccountProperties serializes strong account properties for PAM accounts.
func serializePamAccountProperties(accountModel map[string]interface{}) (map[string]interface{}, error) {
	properties := make(map[string]interface{})

	for _, field := range pamRequiredProperties {
		if value, ok := accountModel[field]; ok && value != nil {
			properties[field] = value
		} else {
			return nil, fmt.Errorf("%s is required for PAM accounts", field)
		}
	}

	return properties, nil
}

// serializePlatformAccountProperties serializes strong account properties for database platforms.
func serializePlatformAccountProperties(platform string, accountModel map[string]interface{}) (map[string]interface{}, error) {
	properties := map[string]interface{}{
		"platform": platform,
	}

	requiredFields, ok := platformToRequiredAccountProperties[platform]
	if !ok {
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
	for _, field := range requiredFields {
		if value, ok := accountModel[field]; ok && hasValue(value) {
			properties[field] = value
		} else {
			return nil, fmt.Errorf("%s is required for platform %s", field, platform)
		}
	}

	optionalFields, hasOptional := platformToOptionalAccountProperties[platform]
	if hasOptional {
		for _, field := range optionalFields {
			if value, ok := accountModel[field]; ok && hasValue(value) {
				properties[field] = value
			}
		}
	}

	return properties, nil
}

// serializeAccountProperties serializes AccountProperties for API requests based on platform.
func serializeAccountProperties(storeType string, accountModel map[string]interface{}) (map[string]interface{}, error) {
	if storeType == dbstrongaccountsmodels.PAM {
		return serializePamAccountProperties(accountModel)
	}

	platform, hasPlatform := accountModel["platform"].(string)
	if !hasPlatform || platform == "" {
		return nil, errors.New("platform is required for managed accounts")
	}

	return serializePlatformAccountProperties(platform, accountModel)
}

// serializePasswordSecretObject serializes PasswordSecretObject based on platform.
func serializePasswordSecretObject(platform string, accountModel map[string]interface{}, isOptional bool) (map[string]interface{}, error) {
	requiredFields, ok := platformToRequiredSecretPasswordObjectProperties[platform]
	if !ok {
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
	hasPassword := hasValue(accountModel["password"])
	hasSecretAccessKey := hasValue(accountModel["secret_access_key"])
	hasPasswordField := hasPassword || hasSecretAccessKey

	if isOptional && !hasPasswordField {
		return nil, nil
	}

	isAWS := platform == PlatformAWSAccessKeys
	if hasPasswordField {
		if isAWS && !hasSecretAccessKey {
			return nil, fmt.Errorf("AWSAccessKeys platform requires secret_access_key in password_secret_object")
		}
		if !isAWS && hasSecretAccessKey {
			return nil, fmt.Errorf("%s platform requires password in password_secret_object", platform)
		}
	}

	secretPasswordObject := make(map[string]interface{})
	for _, field := range requiredFields {
		if value, ok := accountModel[field]; ok && hasValue(value) {
			secretPasswordObject[field] = value
		} else {
			if isOptional {
				return nil, fmt.Errorf("%s is required for platform %s when updating password", field, platform)
			}
			return nil, fmt.Errorf("%s is required for platform %s", field, platform)
		}
	}

	return secretPasswordObject, nil
}

// deserializeManagedAccountProperties deserializes AccountProperties from API response.
func (s *IdsecSIADBStrongAccountsService) deserializeManagedAccountProperties(accountModel map[string]interface{}, accountProperties map[string]interface{}) error {
	platform, ok := accountProperties["platform"].(string)
	if !ok {
		s.Logger.Warning("Missing platform for managed strong account, fallback to all fields within properties")
		for key, value := range accountProperties {
			if _, ok := accountModel[key]; !ok {
				accountModel[key] = value
			}
		}
		return nil
	}
	accountModel["platform"] = platform

	requiredFields, ok := platformToRequiredAccountProperties[platform]
	if !ok {
		s.Logger.Warning("unsupported platform: %s", platform)
		return nil
	}
	for _, field := range requiredFields {
		if value, ok := accountProperties[field]; ok && hasValue(value) {
			accountModel[field] = value
		} else {
			s.Logger.Warning("Failed to deserialize strong account properties for platform %s: %s is missing", platform, field)
		}
	}
	optionalFields, hasOptional := platformToOptionalAccountProperties[platform]
	if hasOptional {
		for _, field := range optionalFields {
			if value, ok := accountProperties[field]; ok && hasValue(value) {
				accountModel[field] = value
			}
		}
	}
	return nil
}

func (s *IdsecSIADBStrongAccountsService) deserializePamAccountProperties(accountModel map[string]interface{}, accountProperties map[string]interface{}) error {
	for _, field := range pamRequiredProperties {
		if value, ok := accountProperties[field]; ok && hasValue(value) {
			accountModel[field] = value
		} else {
			s.Logger.Error("Failed to fully deserialize PAM strong account properties: %s is missing", field)
		}
	}
	return nil
}

func (s *IdsecSIADBStrongAccountsService) deserializeStrongAccount(strongAccountJSONMap map[string]interface{}) error {
	if strongAccountID, ok := strongAccountJSONMap["id"].(string); ok {
		strongAccountJSONMap["strong_account_id"] = strongAccountID
	}
	storeType, ok := strongAccountJSONMap["store_type"].(string)
	if !ok {
		return fmt.Errorf("store_type is required")
	}
	if storeType == dbstrongaccountsmodels.PAM {
		err := s.deserializePamAccountProperties(strongAccountJSONMap, strongAccountJSONMap["account_properties"].(map[string]interface{}))
		if err != nil {
			return err
		}
	} else {
		err := s.deserializeManagedAccountProperties(strongAccountJSONMap, strongAccountJSONMap["account_properties"].(map[string]interface{}))
		if err != nil {
			return err
		}
	}
	delete(strongAccountJSONMap, "account_properties")
	return nil
}

// Create adds a new strong account to the Idsec SIA DB.
func (s *IdsecSIADBStrongAccountsService) Create(addStrongAccount *dbstrongaccountsmodels.IdsecSIADBAddStrongAccount) (*dbstrongaccountsmodels.IdsecSIADBStrongAccount, error) {
	if addStrongAccount.StoreType == "" {
		return nil, errors.New("store_type is required")
	}
	if addStrongAccount.Name == "" {
		return nil, errors.New("name is required")
	}

	strongAccountModel := make(map[string]interface{})
	if err := mapstructure.Decode(addStrongAccount, &strongAccountModel); err != nil {
		return nil, fmt.Errorf("failed to decode add strong account: %w", err)
	}
	addStrongAccountJSON := map[string]interface{}{
		"store_type": addStrongAccount.StoreType,
		"name":       addStrongAccount.Name,
	}
	serializedStrongAccountProperties, err := serializeAccountProperties(addStrongAccount.StoreType, strongAccountModel)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize strong account properties: %w", err)
	}
	addStrongAccountJSON["account_properties"] = serializedStrongAccountProperties
	switch addStrongAccount.StoreType {
	case dbstrongaccountsmodels.Managed:
		serializedPasswordSecretObject, err := serializePasswordSecretObject(addStrongAccount.Platform, strongAccountModel, false)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize password secret object: %w", err)
		}
		addStrongAccountJSON["password_secret_object"] = serializedPasswordSecretObject
	}
	addStrongAccountJSONCamel := common.ConvertToCamelCase(addStrongAccountJSON, nil)
	response, err := s.ISPClient().Post(context.Background(), strongAccountsURL, addStrongAccountJSONCamel)
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
		return nil, fmt.Errorf("failed to add account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	strongAccountJSONResponse, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	strongAccountJSONResponseMap := strongAccountJSONResponse.(map[string]interface{})

	s.Logger.Info("Account added successfully with id [%s]", strongAccountJSONResponseMap["id"].(string))

	return s.Get(&dbstrongaccountsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: strongAccountJSONResponseMap["id"].(string)})
}

// Update updates an existing strong account in the Idsec SIA DB.
func (s *IdsecSIADBStrongAccountsService) Update(updateStrongAccount *dbstrongaccountsmodels.IdsecSIADBUpdateStrongAccount) (*dbstrongaccountsmodels.IdsecSIADBStrongAccount, error) {
	if updateStrongAccount.StrongAccountID == "" {
		return nil, errors.New("id is required")
	}
	s.Logger.Info("Updating existing db strong account with id [%s]", updateStrongAccount.StrongAccountID)

	existingStrongAccount, err := s.Get(&dbstrongaccountsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: updateStrongAccount.StrongAccountID})
	if err != nil {
		return nil, err
	}
	existingStrongAccountMap := make(map[string]interface{})
	if err := mapstructure.Decode(existingStrongAccount, &existingStrongAccountMap); err != nil {
		return nil, fmt.Errorf("failed to decode update account: %w", err)
	}

	updateAccountModel := make(map[string]interface{})
	if err := mapstructure.Decode(updateStrongAccount, &updateAccountModel); err != nil {
		return nil, fmt.Errorf("failed to decode update account: %w", err)
	}

	hasPasswordInUpdate := hasValue(updateAccountModel["password"]) || hasValue(updateAccountModel["secret_access_key"])

	switch updateStrongAccount.StoreType {
	case dbstrongaccountsmodels.Managed:
		if err := validateManagedAccountUpdateFields(updateAccountModel); err != nil {
			return nil, err
		}
	case dbstrongaccountsmodels.PAM:
		if err := validatePamAccountUpdateFields(updateAccountModel); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported store_type: %s", updateStrongAccount.StoreType)
	}

	strongAccountModel := make(map[string]interface{})
	if err := mapstructure.Decode(updateStrongAccount, &strongAccountModel); err != nil {
		return nil, fmt.Errorf("failed to decode update account: %w", err)
	}
	for field, existingValue := range existingStrongAccountMap {
		if fieldValue, ok := strongAccountModel[field]; ok && hasValue(fieldValue) {
			continue
		}
		if hasValue(existingValue) {
			strongAccountModel[field] = existingValue
		}
	}

	updateStrongAccountJSON := map[string]interface{}{
		"store_type": updateStrongAccount.StoreType,
		"name":       updateStrongAccount.Name,
	}
	serializedStrongAccountProperties, err := serializeAccountProperties(updateStrongAccount.StoreType, strongAccountModel)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize account properties: %w", err)
	}
	updateStrongAccountJSON["account_properties"] = serializedStrongAccountProperties
	switch updateStrongAccount.StoreType {
	case dbstrongaccountsmodels.Managed:
		if hasPasswordInUpdate {
			platform, ok := strongAccountModel["platform"].(string)
			if !ok || platform == "" {
				return nil, fmt.Errorf("platform is required for managed accounts")
			}
			serializedPasswordSecretObject, err := serializePasswordSecretObject(platform, updateAccountModel, true)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize password secret object: %w", err)
			}
			if serializedPasswordSecretObject != nil {
				updateStrongAccountJSON["password_secret_object"] = serializedPasswordSecretObject
			}
		}
	}
	updateStrongAccountJSONCamel := common.ConvertToCamelCase(updateStrongAccountJSON, nil)
	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(strongAccountURL, updateStrongAccount.StrongAccountID), updateStrongAccountJSONCamel)
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
		return nil, fmt.Errorf("failed to update account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	strongAccountResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	strongAccountResponseJSONMap := strongAccountResponseJSON.(map[string]interface{})

	return s.Get(&dbstrongaccountsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: strongAccountResponseJSONMap["id"].(string)})
}

// Delete deletes a strong account from the Idsec SIA DB.
func (s *IdsecSIADBStrongAccountsService) Delete(deleteStrongAccount *dbstrongaccountsmodels.IdsecSIADBDeleteStrongAccount) error {
	if deleteStrongAccount.StrongAccountID == "" {
		return errors.New("id is required")
	}
	s.Logger.Info("Deleting db strong account by id [%s]", deleteStrongAccount.StrongAccountID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(strongAccountURL, deleteStrongAccount.StrongAccountID), nil, nil)
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
		return fmt.Errorf("failed to delete db strong account [%s] - [%d]", common.SerializeResponseToJSON(response.Body), response.StatusCode)
	}
	return nil
}

// Get retrieves a strong account from the Idsec SIA DB by its ID.
func (s *IdsecSIADBStrongAccountsService) Get(getStrongAccount *dbstrongaccountsmodels.IdsecSIADBGetStrongAccount) (*dbstrongaccountsmodels.IdsecSIADBStrongAccount, error) {
	if getStrongAccount.StrongAccountID == "" {
		return nil, errors.New("id is required")
	}
	s.Logger.Info("Getting db strong account [%s]", getStrongAccount.StrongAccountID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(strongAccountURL, getStrongAccount.StrongAccountID), nil)
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
		return nil, fmt.Errorf("failed to get db strong account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	strongAccountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	strongAccountJSONMap := strongAccountJSON.(map[string]interface{})
	err = s.deserializeStrongAccount(strongAccountJSONMap)
	if err != nil {
		return nil, err
	}
	if strongAccountID, ok := strongAccountJSONMap["id"].(string); ok {
		strongAccountJSONMap["strong_account_id"] = strongAccountID
	}
	var strongAccount dbstrongaccountsmodels.IdsecSIADBStrongAccount
	err = mapstructure.Decode(strongAccountJSONMap, &strongAccount)
	if err != nil {
		return nil, err
	}
	return &strongAccount, nil
}

// List retrieves all strong accounts by automatically paginating through all pages.
func (s *IdsecSIADBStrongAccountsService) List() (<-chan *IdsecSIADBStrongAccountPage, error) {
	s.Logger.Info("Listing all db strong accounts (with automatic pagination)")

	pageChannel := make(chan *IdsecSIADBStrongAccountPage)

	go func() {
		defer close(pageChannel)

		nextCursor := ""

		for {
			queryParams := make(map[string]string)
			queryParams["limit"] = fmt.Sprintf("%d", defaultLimit)
			if nextCursor != "" {
				queryParams["cursor"] = nextCursor
			}

			s.Logger.Info("Fetching db strong accounts")
			response, err := s.ISPClient().Get(context.Background(), strongAccountsURL, queryParams)
			if err != nil {
				s.Logger.Error("Failed to fetch db strong accounts: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to fetch db strong accounts - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			strongAccountsJSON, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}

			strongAccountsJSONMap := strongAccountsJSON.(map[string]interface{})
			if items, ok := strongAccountsJSONMap["items"].([]interface{}); ok {
				for _, item := range items {
					if itemMap, ok := item.(map[string]interface{}); ok {
						err := s.deserializeStrongAccount(itemMap)
						if err != nil {
							name, _ := itemMap["name"].(string)
							id, _ := itemMap["id"].(string)
							s.Logger.Error("Failed to deserialize strong account [%s - %s]: %v", id, name, err)
							return
						}
					}
				}
			}

			var pageResponse dbstrongaccountsmodels.IdsecSIADBStrongAccountsList
			err = mapstructure.Decode(strongAccountsJSONMap, &pageResponse)
			if err != nil {
				s.Logger.Error("Failed to decode page response: %v", err)
				return
			}

			itemPointers := make([]*dbstrongaccountsmodels.IdsecSIADBStrongAccount, len(pageResponse.Items))
			for i := range pageResponse.Items {
				itemPointers[i] = &pageResponse.Items[i]
			}

			pageChannel <- &common.IdsecPage[dbstrongaccountsmodels.IdsecSIADBStrongAccount]{
				Items: itemPointers,
			}

			if pageResponse.NextCursor == "" {
				s.Logger.Info("Retrieved all db strong accounts")
				break
			}
			nextCursor = pageResponse.NextCursor
		}
	}()

	return pageChannel, nil
}

// ListBy retrieves strong accounts filtered by the given criteria (client-side filtering).
func (s *IdsecSIADBStrongAccountsService) ListBy(filter *dbstrongaccountsmodels.IdsecSIADBStrongAccountsFilter) (<-chan *IdsecSIADBStrongAccountPage, error) {
	s.Logger.Info("Listing db strong accounts with filter [%v]", filter)

	if filter.Name != "" {
		if _, err := regexp.Compile(filter.Name); err != nil {
			return nil, fmt.Errorf("invalid name regex pattern '%s': %w", filter.Name, err)
		}
	}

	allPages, err := s.List()
	if err != nil {
		return nil, err
	}

	filteredPageChannel := make(chan *IdsecSIADBStrongAccountPage)
	go func() {
		defer close(filteredPageChannel)

		for page := range allPages {
			filteredItems := make([]*dbstrongaccountsmodels.IdsecSIADBStrongAccount, 0)

			for _, account := range page.Items {
				if filter.StoreType != "" && account.StoreType != filter.StoreType {
					continue
				}
				if filter.Platform != "" && account.Platform != filter.Platform {
					continue
				}
				if filter.Name != "" {
					matched, err := regexp.MatchString(filter.Name, account.Name)
					if err != nil || !matched {
						continue
					}
				}

				filteredItems = append(filteredItems, account)
			}

			if len(filteredItems) > 0 {
				filteredPageChannel <- &common.IdsecPage[dbstrongaccountsmodels.IdsecSIADBStrongAccount]{
					Items: filteredItems,
				}
			}
		}
	}()

	return filteredPageChannel, nil
}
