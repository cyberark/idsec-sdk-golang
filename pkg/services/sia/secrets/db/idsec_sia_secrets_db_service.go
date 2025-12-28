package dbsecrets

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
	dbsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/models"
	dbworkspacemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
)

const (
	secretsURL        = "/api/adb/secretsmgmt/secrets"
	secretURL         = "/api/adb/secretsmgmt/secrets/%s"
	enableSecretURL   = "/api/adb/secretsmgmt/secrets/%s/enable"
	disableSecretURL  = "/api/adb/secretsmgmt/secrets/%s/disable"
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

const (
	defaultLimit = 500
	minLimit     = 1
	maxLimit     = 1000
)

var (
	// platformToRequiredAccountProperties maps each platform to its required account properties.
	// Matches Python managed_account_request.py requirements.
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
		PlatformPostgreSQL:    {"port", "database", "dsn", "address"},                             // Optional: address, port, database, dsn
		PlatformMySQL:         {"port", "database", "dsn", "address"},                             // Optional: address, port, database, dsn
		PlatformMariaDB:       {"port", "database", "dsn", "address"},                             // Optional: address, port, database, dsn
		PlatformMSSql:         {"port", "database", "dsn", "address", "reconcile_is_win_account"}, // Optional: address, port, database, dsn, reconcile_is_win_account
		PlatformOracle:        {"port", "database", "dsn", "address"},                             // Optional: address, port, database, dsn
		PlatformMongoDB:       {"port", "auth_database", "dsn", "replica_set", "use_ssl"},         // Optional: port, auth_database, dsn, replica_set, use_ssl
		PlatformDB2UnixSSH:    {},                                                                 // No optional fields
		PlatformDomainAccount: {},                                                                 // No optional fields
		PlatformAWSAccessKeys: {},                                                                 // No optional fields
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

// IdsecSIASecretsDBService is the service for managing db secrets.
type IdsecSIASecretsDBService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSIASecretsDBService creates a new instance of IdsecSIASecretsDBService.
func NewIdsecSIASecretsDBService(authenticators ...auth.IdsecAuth) (*IdsecSIASecretsDBService, error) {
	secretsDBService := &IdsecSIASecretsDBService{}
	var secretsDBServiceInterface services.IdsecService = secretsDBService
	baseService, err := services.NewIdsecBaseService(secretsDBServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", secretsDBService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	secretsDBService.client = client
	secretsDBService.ispAuth = ispAuth
	secretsDBService.IdsecBaseService = baseService
	return secretsDBService, nil
}

func (s *IdsecSIASecretsDBService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIASecretsDBService) parseSecretTagsIntoMap(secretJSONMap map[string]interface{}) {
	if tags, ok := secretJSONMap["tags"].([]interface{}); ok {
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
		secretJSONMap["tags"] = parsedTags
	}
}

func (s *IdsecSIASecretsDBService) listSecretsWithFilters(secretType string, tags map[string]string) (*dbsecretsmodels.IdsecSIADBSecretMetadataList, error) {
	params := make(map[string]string)
	if secretType != "" {
		params["secret_type"] = secretType
	}
	for key, value := range tags {
		params[key] = value
	}
	response, err := s.client.Get(context.Background(), secretsURL, params)
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
		return nil, fmt.Errorf("failed to list secrets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	secretsJSONMap := secretsJSON.(map[string]interface{})
	if secrets, ok := secretsJSONMap["secrets"].([]interface{}); ok {
		for _, secret := range secrets {
			if secretMap, ok := secret.(map[string]interface{}); ok {
				s.parseSecretTagsIntoMap(secretMap)
			}
		}
	}
	var secretsList dbsecretsmodels.IdsecSIADBSecretMetadataList
	err = mapstructure.Decode(secretsJSONMap, &secretsList)

	if err != nil {
		s.Logger.Error("Failed to parse list secrets response [%v]", err)
		return nil, fmt.Errorf("failed to parse list secrets response: [%v]", err)
	}
	return &secretsList, nil
}

// Deprecated: Use AddStrongAccount instead. This method uses the legacy API
// which will be removed in a future version.
// AddSecret adds a new secret to the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) AddSecret(addSecret *dbsecretsmodels.IdsecSIADBAddSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
	s.Logger.Warning("⚠️ Deprecated: Use AddStrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if addSecret.StoreType == "" {
		storeType, ok := dbsecretsmodels.SecretTypeToStoreDict[addSecret.SecretType]
		if !ok {
			return nil, errors.New("invalid secret type")
		}
		addSecret.StoreType = storeType
	}
	addSecretJSON := map[string]interface{}{
		"secret_store": map[string]interface{}{
			"store_type": addSecret.StoreType,
		},
		"secret_name": addSecret.SecretName,
		"secret_type": addSecret.SecretType,
	}
	if addSecret.Description != "" {
		addSecretJSON["description"] = addSecret.Description
	}
	if addSecret.Purpose != "" {
		addSecretJSON["purpose"] = addSecret.Purpose
	}
	if addSecret.Tags != nil {
		addSecretJSON["tags"] = make([]dbworkspacemodels.IdsecSIADBTag, len(addSecret.Tags))
		idx := 0
		for key, value := range addSecret.Tags {
			if key == "" {
				continue
			}
			addSecretJSON["tags"].([]dbworkspacemodels.IdsecSIADBTag)[idx] = dbworkspacemodels.IdsecSIADBTag{
				Key:   key,
				Value: value,
			}
			idx++
		}
	}
	switch addSecret.SecretType {
	case dbsecretsmodels.UsernamePassword:
		if addSecret.Username == "" || addSecret.Password == "" {
			return nil, errors.New("username and password must be supplied for username_password type")
		}
		addSecretJSON["secret_data"] = map[string]interface{}{
			"username": addSecret.Username,
			"password": addSecret.Password,
		}
	case dbsecretsmodels.CyberArkPAM:
		if addSecret.PAMSafe == "" || addSecret.PAMAccountName == "" {
			return nil, errors.New("pam safe and pam account name must be supplied for pam type")
		}
		addSecretJSON["secret_link"] = map[string]interface{}{
			"safe":         addSecret.PAMSafe,
			"account_name": addSecret.PAMAccountName,
		}
	case dbsecretsmodels.IAMUser:
		if addSecret.IAMAccessKeyID == "" || addSecret.IAMSecretAccessKey == "" || addSecret.IAMAccount == "" || addSecret.IAMUsername == "" {
			return nil, errors.New("all IAM parameters must be supplied for iam_user type")
		}
		addSecretJSON["secret_data"] = map[string]interface{}{
			"account":           addSecret.IAMAccount,
			"username":          addSecret.IAMUsername,
			"access_key_id":     addSecret.IAMAccessKeyID,
			"secret_access_key": addSecret.IAMSecretAccessKey,
		}
	case dbsecretsmodels.AtlasAccessKeys:
		if addSecret.AtlasPublicKey == "" || addSecret.AtlasPrivateKey == "" {
			return nil, errors.New("public key and private key must be supplied for atlas type")
		}
		addSecretJSON["secret_data"] = map[string]interface{}{
			"public_key":  addSecret.AtlasPublicKey,
			"private_key": addSecret.AtlasPrivateKey,
		}
	default:
		return nil, fmt.Errorf("unsupported secret type: %s", addSecret.SecretType)
	}
	response, err := s.client.Post(context.Background(), secretsURL, addSecretJSON)
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
		return nil, fmt.Errorf("failed to add secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	secretJSONMap := secretJSON.(map[string]interface{})
	s.parseSecretTagsIntoMap(secretJSONMap)
	var secret dbsecretsmodels.IdsecSIADBSecretMetadata
	err = mapstructure.Decode(secretJSONMap, &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// Deprecated: Use UpdateStrongAccount instead. This method uses the legacy API
// which will be removed in a future version.
// UpdateSecret updates an existing secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) UpdateSecret(updateSecret *dbsecretsmodels.IdsecSIADBUpdateSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
	s.Logger.Warning("⚠️ Deprecated: Use UpdateStrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if updateSecret.SecretName != "" && updateSecret.SecretID == "" {
		secrets, err := s.ListSecretsBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: updateSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return nil, fmt.Errorf("failed to find secret by name: %v", err)
		}
		updateSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Updating existing db secret with id [%s]", updateSecret.SecretID)
	updateSecretMap := make(map[string]interface{})
	if updateSecret.NewSecretName != "" {
		updateSecretMap["secret_name"] = updateSecret.NewSecretName
	} else if updateSecret.SecretName != "" {
		updateSecretMap["secret_name"] = updateSecret.SecretName
	}
	if updateSecret.Description != "" {
		updateSecretMap["description"] = updateSecret.Description
	}
	if updateSecret.Purpose != "" {
		updateSecretMap["purpose"] = updateSecret.Purpose
	}
	if updateSecret.Tags != nil {
		updateSecretMap["tags"] = make([]dbworkspacemodels.IdsecSIADBTag, len(updateSecret.Tags))
		idx := 0
		for key, value := range updateSecret.Tags {
			if key == "" {
				continue
			}
			updateSecretMap["tags"].([]dbworkspacemodels.IdsecSIADBTag)[idx] = dbworkspacemodels.IdsecSIADBTag{
				Key:   key,
				Value: value,
			}
			idx++
		}
	}
	if updateSecret.PAMAccountName != "" || updateSecret.PAMSafe != "" {
		if updateSecret.PAMAccountName == "" || updateSecret.PAMSafe == "" {
			return nil, errors.New("both pam safe and pam account name must be supplied for pam secret")
		}
		updateSecretMap["secret_link"] = map[string]interface{}{
			"safe":         updateSecret.PAMSafe,
			"account_name": updateSecret.PAMAccountName,
		}
	}
	if updateSecret.Username != "" || updateSecret.Password != "" {
		if updateSecret.Username == "" || updateSecret.Password == "" {
			return nil, errors.New("both username and password must be supplied for username_password secret")
		}
		updateSecretMap["secret_data"] = map[string]interface{}{
			"username": updateSecret.Username,
			"password": updateSecret.Password,
		}
	}

	if updateSecret.IAMAccessKeyID != "" || updateSecret.IAMSecretAccessKey != "" || updateSecret.IAMAccount != "" || updateSecret.IAMUsername != "" {
		if updateSecret.IAMAccessKeyID == "" || updateSecret.IAMSecretAccessKey == "" || updateSecret.IAMAccount == "" || updateSecret.IAMUsername == "" {
			return nil, errors.New("all IAM parameters must be supplied for iam_user secret")
		}
		updateSecretMap["secret_data"] = map[string]interface{}{
			"account":           updateSecret.IAMAccount,
			"username":          updateSecret.IAMUsername,
			"access_key_id":     updateSecret.IAMAccessKeyID,
			"secret_access_key": updateSecret.IAMSecretAccessKey,
		}
	}

	if updateSecret.AtlasPublicKey != "" || updateSecret.AtlasPrivateKey != "" {
		if updateSecret.AtlasPublicKey == "" || updateSecret.AtlasPrivateKey == "" {
			return nil, errors.New("both public key and private key must be supplied for atlas secret")
		}
		updateSecretMap["secret_data"] = map[string]interface{}{
			"public_key":  updateSecret.AtlasPublicKey,
			"private_key": updateSecret.AtlasPrivateKey,
		}
	}
	response, err := s.client.Patch(context.Background(), fmt.Sprintf(secretURL, updateSecret.SecretID), updateSecretMap)
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
		return nil, fmt.Errorf("failed to update secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	secretJSONMap := secretJSON.(map[string]interface{})
	s.parseSecretTagsIntoMap(secretJSONMap)
	var secret dbsecretsmodels.IdsecSIADBSecretMetadata
	err = mapstructure.Decode(secretJSONMap, &secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Deprecated: Use DeleteStrongAccount instead. This method uses the legacy API
// which will be removed in a future version.
// DeleteSecret deletes a secret from the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) DeleteSecret(deleteSecret *dbsecretsmodels.IdsecSIADBDeleteSecret) error {
	s.Logger.Warning("⚠️ Deprecated: Use DeleteStrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if deleteSecret.SecretName != "" && deleteSecret.SecretID == "" {
		secrets, err := s.ListSecretsBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: deleteSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		deleteSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Deleting db secret by id [%s]", deleteSecret.SecretID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(secretURL, deleteSecret.SecretID), nil, nil)
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
		return fmt.Errorf("failed to delete db secret [%s] - [%d]", common.SerializeResponseToJSON(response.Body), response.StatusCode)
	}
	return nil
}

// Deprecated: Use ListStrongAccounts instead. This method uses the legacy API
// which will be removed in a future version.
// ListSecrets lists all secrets in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) ListSecrets() (*dbsecretsmodels.IdsecSIADBSecretMetadataList, error) {
	s.Logger.Warning("⚠️ Deprecated: Use ListStrongAccounts instead. This method uses the legacy API which will be removed in a future version.")
	return s.listSecretsWithFilters("", nil)
}

// Deprecated: Use ListStrongAccounts instead. This method uses the legacy API
// which will be removed in a future version.
// ListSecretsBy lists secrets in the Idsec SIA DB by the given filter.
func (s *IdsecSIASecretsDBService) ListSecretsBy(filter *dbsecretsmodels.IdsecSIADBSecretsFilter) (*dbsecretsmodels.IdsecSIADBSecretMetadataList, error) {
	s.Logger.Warning("⚠️ Deprecated: Use ListStrongAccountsBy instead. This method uses the legacy API which will be removed in a future version.")
	secrets, err := s.listSecretsWithFilters(filter.SecretType, filter.Tags)
	if err != nil {
		return nil, err
	}
	if filter.StoreType != "" {
		var filteredSecrets []dbsecretsmodels.IdsecSIADBSecretMetadata
		for _, secret := range secrets.Secrets {
			if secret.SecretStore.StoreType == filter.StoreType {
				filteredSecrets = append(filteredSecrets, secret)
			}
		}
		secrets.Secrets = filteredSecrets
	}
	if filter.SecretName != "" {
		var filteredSecrets []dbsecretsmodels.IdsecSIADBSecretMetadata
		for _, secret := range secrets.Secrets {
			if secret.SecretName != "" {
				matched, _ := regexp.MatchString(filter.SecretName, secret.SecretName)
				if matched {
					filteredSecrets = append(filteredSecrets, secret)
				}
			}
		}
		secrets.Secrets = filteredSecrets
	}
	if filter.IsActive {
		var filteredSecrets []dbsecretsmodels.IdsecSIADBSecretMetadata
		for _, secret := range secrets.Secrets {
			if secret.IsActive == filter.IsActive {
				filteredSecrets = append(filteredSecrets, secret)
			}
		}
		secrets.Secrets = filteredSecrets
	}
	secrets.TotalCount = len(secrets.Secrets)
	return secrets, nil
}

// Deprecated: This method uses the legacy API which will be removed in a future version.
// EnableSecret enables a secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) EnableSecret(enableSecret *dbsecretsmodels.IdsecSIADBEnableSecret) error {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy API which will be removed in a future version.")
	if enableSecret.SecretName != "" && enableSecret.SecretID == "" {
		secrets, err := s.ListSecretsBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: enableSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		enableSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Enabling db secret by id [%s]", enableSecret.SecretID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(enableSecretURL, enableSecret.SecretID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to enable db secret [%s] - [%d]", common.SerializeResponseToJSON(response.Body), response.StatusCode)
	}
	return nil
}

// Deprecated: This method uses the legacy API which will be removed in a future version.
// DisableSecret disables a secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) DisableSecret(enableSecret *dbsecretsmodels.IdsecSIADBDisableSecret) error {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy API which will be removed in a future version.")
	if enableSecret.SecretName != "" && enableSecret.SecretID == "" {
		secrets, err := s.ListSecretsBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: enableSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		enableSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Disabling db secret by id [%s]", enableSecret.SecretID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(disableSecretURL, enableSecret.SecretID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to disable db secret [%s] - [%d]", common.SerializeResponseToJSON(response.Body), response.StatusCode)
	}
	return nil
}

// Deprecated: Use StrongAccount instead. This method uses the legacy API
// which will be removed in a future version.
// Secret retrieves a secret from the Idsec SIA DB by its ID.
func (s *IdsecSIASecretsDBService) Secret(getSecret *dbsecretsmodels.IdsecSIADBGetSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
	s.Logger.Warning("⚠️ Deprecated: Use StrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if getSecret.SecretName != "" && getSecret.SecretID == "" {
		secrets, err := s.ListSecretsBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: getSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return nil, fmt.Errorf("failed to find secret by name: %v", err)
		}
		getSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Retrieving db secret by id [%s]", getSecret.SecretID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(secretURL, getSecret.SecretID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)

	// Check response status
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve db secret [%s] - [%d]", common.SerializeResponseToJSON(response.Body), response.StatusCode)
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		s.Logger.Error("Failed to parse db secret response [%v]", err)
		return nil, fmt.Errorf("failed to parse db secret response: %w", err)
	}
	secretJSONMap := secretJSON.(map[string]interface{})
	s.parseSecretTagsIntoMap(secretJSONMap)
	var secret dbsecretsmodels.IdsecSIADBSecretMetadata
	err = mapstructure.Decode(secretJSONMap, &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

// Deprecated: This method uses the legacy API which will be removed in a future version.
// SecretsStats retrieves the statistics of secrets in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) SecretsStats() (*dbsecretsmodels.IdsecSIADBSecretsStats, error) {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy APIs which will be removed in a future version.")
	s.Logger.Info("Calculating secrets statistics")
	secretsList, err := s.ListSecrets()
	if err != nil {
		return nil, err
	}
	secretsStats := &dbsecretsmodels.IdsecSIADBSecretsStats{
		SecretsCountBySecretType: make(map[string]int),
		SecretsCountByStoreType:  make(map[string]int),
	}
	secretsStats.SecretsCount = len(secretsList.Secrets)
	for _, secret := range secretsList.Secrets {
		if secret.IsActive {
			secretsStats.ActiveSecretsCount++
		} else {
			secretsStats.InactiveSecretsCount++
		}
		if secret.SecretType != "" {
			if _, ok := secretsStats.SecretsCountBySecretType[secret.SecretType]; !ok {
				secretsStats.SecretsCountBySecretType[secret.SecretType] = 0
			}
			secretsStats.SecretsCountBySecretType[secret.SecretType]++
		}
		if secret.SecretStore.StoreType != "" {
			if _, ok := secretsStats.SecretsCountByStoreType[secret.SecretStore.StoreType]; !ok {
				secretsStats.SecretsCountByStoreType[secret.SecretStore.StoreType] = 0
			}
			secretsStats.SecretsCountByStoreType[secret.SecretStore.StoreType]++
		}
	}
	return secretsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSIASecretsVMService.
func (s *IdsecSIASecretsDBService) ServiceConfig() services.IdsecServiceConfig {
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
	// Platform is a required field for all managed accounts
	platform, ok := updateAccountModel["platform"].(string)
	if !ok || platform == "" {
		return fmt.Errorf("platform is required for managed accounts (all required fields must be provided in update request)")
	}
	// Validate required account property fields for the platform are provided in the update request
	// Note: password is NOT included here - it's optional for updates
	requiredFields, ok := platformToRequiredAccountProperties[platform]
	if !ok {
		return fmt.Errorf("unsupported platform: %s", platform)
	}
	// Validate all required fields for this platform are provided
	for _, field := range requiredFields {
		if value, ok := updateAccountModel[field]; !ok || !hasValue(value) {
			return fmt.Errorf("%s is required for platform %s (all required fields must be provided in update request)", field, platform)
		}
	}
	return nil
}

// validatePamAccountUpdateFields validates that all required fields for PAM accounts are provided in the update request.
func validatePamAccountUpdateFields(updateAccountModel map[string]interface{}) error {
	// Validate required fields for PAM accounts are provided in the update request
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

	// Validate and add required fields
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

	// Validate and add required fields
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

	// Add optional fields if present
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
	// PAM accounts use different fields (safe, accountName)
	if storeType == dbsecretsmodels.PAM {
		return serializePamAccountProperties(accountModel)
	}

	// Managed accounts require a platform
	platform, hasPlatform := accountModel["platform"].(string)
	if !hasPlatform || platform == "" {
		return nil, errors.New("platform is required for managed accounts")
	}

	return serializePlatformAccountProperties(platform, accountModel)
}

// serializePasswordSecretObject serializes PasswordSecretObject based on platform.
// If isOptional is true, returns nil if no password fields are provided (for updates).
// If isOptional is false, returns an error if password fields are missing (for creates).
// Validates that the correct password type matches the platform (password for most, secret_access_key for AWS).
func serializePasswordSecretObject(platform string, accountModel map[string]interface{}, isOptional bool) (map[string]interface{}, error) {
	requiredFields, ok := platformToRequiredSecretPasswordObjectProperties[platform]
	if !ok {
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
	// Check if any password field is provided
	hasPassword := hasValue(accountModel["password"])
	hasSecretAccessKey := hasValue(accountModel["secret_access_key"])
	hasPasswordField := hasPassword || hasSecretAccessKey

	// If password is optional and not provided, return nil
	if isOptional && !hasPasswordField {
		return nil, nil
	}

	// Validate that the correct password type is provided for the platform
	isAWS := platform == PlatformAWSAccessKeys
	if hasPasswordField {
		if isAWS && !hasSecretAccessKey {
			return nil, fmt.Errorf("AWSAccessKeys platform requires secret_access_key in password_secret_object")
		}
		if !isAWS && hasSecretAccessKey {
			return nil, fmt.Errorf("%s platform requires password in password_secret_object", platform)
		}
	}

	// Validate that the required field is provided
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

// deserializeAccountProperties deserializes AccountProperties from API response.
// The API response uses camelCase field names (e.g., "accountProperties" at top level,
// and nested fields like "awsID", "username", etc. are also in camelCase).
// The common.DeserializeJSONSnake function converts snake_case to camelCase, so the
// account_properties nested map should already be in camelCase format.
func (s *IdsecSIASecretsDBService) deserializeManagedAccountProperties(accountModel map[string]interface{}, accountProperties map[string]interface{}) error {
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

func (s *IdsecSIASecretsDBService) deserializePamAccountProperties(accountModel map[string]interface{}, accountProperties map[string]interface{}) error {
	for _, field := range pamRequiredProperties {
		if value, ok := accountProperties[field]; ok && hasValue(value) {
			accountModel[field] = value
		} else {
			s.Logger.Error("Failed to fully deserialize PAM strong account properties: %s is missing", field)
		}
	}
	return nil
}

func (s *IdsecSIASecretsDBService) deserializeStrongAccount(strongAccountJSONMap map[string]interface{}) error {
	if strongAccountID, ok := strongAccountJSONMap["id"].(string); ok {
		strongAccountJSONMap["strong_account_id"] = strongAccountID
	}
	storeType, ok := strongAccountJSONMap["store_type"].(string)
	if !ok {
		return fmt.Errorf("store_type is required")
	}
	if storeType == dbsecretsmodels.PAM {
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

// AddStrongAccount adds a new strong account to the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) AddStrongAccount(addStrongAccount *dbsecretsmodels.IdsecSIADBAddStrongAccount) (*dbsecretsmodels.IdsecSIADBDatabaseStrongAccount, error) {
	if addStrongAccount.StoreType == "" {
		return nil, errors.New("store_type is required")
	}
	if addStrongAccount.Name == "" {
		return nil, errors.New("name is required")
	}

	// Convert struct to map for serialization
	strongAccountModel := make(map[string]interface{})
	if err := mapstructure.Decode(addStrongAccount, &strongAccountModel); err != nil {
		return nil, fmt.Errorf("failed to decode add strong account: %w", err)
	}
	// Serialize strong account properties based on store type and platform
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
	case dbsecretsmodels.Managed:
		serializedPasswordSecretObject, err := serializePasswordSecretObject(addStrongAccount.Platform, strongAccountModel, false)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize password secret object: %w", err)
		}
		addStrongAccountJSON["password_secret_object"] = serializedPasswordSecretObject
	}
	addStrongAccountJSONCamel := common.ConvertToCamelCase(addStrongAccountJSON, nil)
	response, err := s.client.Post(context.Background(), strongAccountsURL, addStrongAccountJSONCamel)
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

	return s.StrongAccount(&dbsecretsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: strongAccountJSONResponseMap["id"].(string)})
}

// UpdateStrongAccount updates an existing strong account in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) UpdateStrongAccount(updateStrongAccount *dbsecretsmodels.IdsecSIADBUpdateStrongAccount) (*dbsecretsmodels.IdsecSIADBDatabaseStrongAccount, error) {
	if updateStrongAccount.StrongAccountID == "" {
		return nil, errors.New("id is required")
	}
	s.Logger.Info("Updating existing db strong account with id [%s]", updateStrongAccount.StrongAccountID)

	existingStrongAccount, err := s.StrongAccount(&dbsecretsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: updateStrongAccount.StrongAccountID})
	if err != nil {
		return nil, err
	}
	existingStrongAccountMap := make(map[string]interface{})
	if err := mapstructure.Decode(existingStrongAccount, &existingStrongAccountMap); err != nil {
		return nil, fmt.Errorf("failed to decode update account: %w", err)
	}

	// Decode the update request to validate it first
	updateAccountModel := make(map[string]interface{})
	if err := mapstructure.Decode(updateStrongAccount, &updateAccountModel); err != nil {
		return nil, fmt.Errorf("failed to decode update account: %w", err)
	}

	// Check if password is provided in the update request (before merging)
	hasPasswordInUpdate := hasValue(updateAccountModel["password"]) || hasValue(updateAccountModel["secret_access_key"])

	// Validate that required fields are provided in the update request (matching Python PUT behavior)
	switch updateStrongAccount.StoreType {
	case dbsecretsmodels.Managed:
		if err := validateManagedAccountUpdateFields(updateAccountModel); err != nil {
			return nil, err
		}
	case dbsecretsmodels.PAM:
		if err := validatePamAccountUpdateFields(updateAccountModel); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported store_type: %s", updateStrongAccount.StoreType)
	}

	// Merge with existing account for serialization (fill in missing fields from existing account)
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
	case dbsecretsmodels.Managed:
		if hasPasswordInUpdate {
			// Get platform from strongAccountModel (from update request, already validated above)
			platform, ok := strongAccountModel["platform"].(string)
			if !ok || platform == "" {
				return nil, fmt.Errorf("platform is required for managed accounts")
			}
			// Use updateAccountModel for password serialization (original update request)
			serializedPasswordSecretObject, err := serializePasswordSecretObject(platform, updateAccountModel, true)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize password secret object: %w", err)
			}
			// Only add to JSON if password object was serialized (not nil)
			if serializedPasswordSecretObject != nil {
				updateStrongAccountJSON["password_secret_object"] = serializedPasswordSecretObject
			}
		}
	}
	updateStrongAccountJSONCamel := common.ConvertToCamelCase(updateStrongAccountJSON, nil)
	response, err := s.client.Put(context.Background(), fmt.Sprintf(strongAccountURL, updateStrongAccount.StrongAccountID), updateStrongAccountJSONCamel)
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

	return s.StrongAccount(&dbsecretsmodels.IdsecSIADBGetStrongAccount{StrongAccountID: strongAccountResponseJSONMap["id"].(string)})
}

// DeleteStrongAccount deletes a strong account from the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) DeleteStrongAccount(deleteStrongAccount *dbsecretsmodels.IdsecSIADBDeleteStrongAccount) error {
	if deleteStrongAccount.StrongAccountID == "" {
		return errors.New("id is required")
	}
	s.Logger.Info("Deleting db strong account by id [%s]", deleteStrongAccount.StrongAccountID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(strongAccountURL, deleteStrongAccount.StrongAccountID), nil, nil)
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

// StrongAccount retrieves a strong account from the Idsec SIA DB by its ID.
func (s *IdsecSIASecretsDBService) StrongAccount(getStrongAccount *dbsecretsmodels.IdsecSIADBGetStrongAccount) (*dbsecretsmodels.IdsecSIADBDatabaseStrongAccount, error) {
	if getStrongAccount.StrongAccountID == "" {
		return nil, errors.New("id is required")
	}
	s.Logger.Info("Getting db strong account [%s]", getStrongAccount.StrongAccountID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(strongAccountURL, getStrongAccount.StrongAccountID), nil)
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
	var strongAccount dbsecretsmodels.IdsecSIADBDatabaseStrongAccount
	err = mapstructure.Decode(strongAccountJSONMap, &strongAccount)
	if err != nil {
		return nil, err
	}
	return &strongAccount, nil
}

// ListStrongAccounts lists strong accounts from the Idsec SIA DB with pagination support.
func (s *IdsecSIASecretsDBService) ListStrongAccounts(listStrongAccounts *dbsecretsmodels.IdsecSIADBListStrongAccounts) (*dbsecretsmodels.IdsecSIADBDatabaseStrongAccountsList, error) {
	limit := defaultLimit
	if listStrongAccounts.Limit != nil {
		limit = *listStrongAccounts.Limit
		if limit < minLimit || limit > maxLimit {
			return nil, fmt.Errorf("limit must be between %d and %d, got %d", minLimit, maxLimit, limit)
		}
	}
	hasCursor := listStrongAccounts.Cursor != ""
	s.Logger.Info("Listing db strong accounts [HasCursor=%v, Limit=%d]",
		hasCursor, limit)

	queryParams := make(map[string]string)
	if hasCursor {
		queryParams["cursor"] = listStrongAccounts.Cursor
	}
	queryParams["limit"] = fmt.Sprintf("%d", limit)

	response, err := s.client.Get(context.Background(), strongAccountsURL, queryParams)
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
		return nil, fmt.Errorf("failed to list db strong accounts - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	strongAccountsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	// Deserialize account properties for each account in the list
	strongAccountsJSONMap := strongAccountsJSON.(map[string]interface{})
	if items, ok := strongAccountsJSONMap["items"].([]interface{}); ok {
		for _, item := range items {
			if itemMap, ok := item.(map[string]interface{}); ok {
				err := s.deserializeStrongAccount(itemMap)
				if err != nil {
					name, _ := itemMap["name"].(string)
					id, _ := itemMap["id"].(string)
					s.Logger.Error("Failed to deserialize strong account [%s - %s]: %v", id, name, err)
					return nil, err
				}
			}
		}
	}

	var listResponse dbsecretsmodels.IdsecSIADBDatabaseStrongAccountsList
	err = mapstructure.Decode(strongAccountsJSONMap, &listResponse)
	if err != nil {
		return nil, err
	}
	return &listResponse, nil
}
