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
	dbsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsdb/models"
	dbworkspacemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"
)

const (
	secretsURL       = "/api/adb/secretsmgmt/secrets"
	secretURL        = "/api/adb/secretsmgmt/secrets/%s"
	enableSecretURL  = "/api/adb/secretsmgmt/secrets/%s/enable"
	disableSecretURL = "/api/adb/secretsmgmt/secrets/%s/disable"
)

// IdsecSIASecretsDBService is the service for managing db secrets.
type IdsecSIASecretsDBService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
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
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", secretsDBService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	secretsDBService.IdsecBaseService = baseService
	secretsDBService.IdsecISPBaseService = ispBaseService
	return secretsDBService, nil
}

func (s *IdsecSIASecretsDBService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
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
	response, err := s.ISPClient().Get(context.Background(), secretsURL, params)
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
// create creates a new secret to the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Create(addSecret *dbsecretsmodels.IdsecSIADBAddSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
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
	response, err := s.ISPClient().Post(context.Background(), secretsURL, addSecretJSON)
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
// Update updates an existing secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Update(updateSecret *dbsecretsmodels.IdsecSIADBUpdateSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
	s.Logger.Warning("⚠️ Deprecated: Use UpdateStrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if updateSecret.SecretName != "" && updateSecret.SecretID == "" {
		secrets, err := s.ListBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: updateSecret.SecretName})
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
	response, err := s.ISPClient().Patch(context.Background(), fmt.Sprintf(secretURL, updateSecret.SecretID), updateSecretMap)
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
// Delete deletes a secret from the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Delete(deleteSecret *dbsecretsmodels.IdsecSIADBDeleteSecret) error {
	s.Logger.Warning("⚠️ Deprecated: Use DeleteStrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if deleteSecret.SecretName != "" && deleteSecret.SecretID == "" {
		secrets, err := s.ListBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: deleteSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		deleteSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Deleting db secret by id [%s]", deleteSecret.SecretID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(secretURL, deleteSecret.SecretID), nil, nil)
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
// List lists all secrets in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) List() (*dbsecretsmodels.IdsecSIADBSecretMetadataList, error) {
	s.Logger.Warning("⚠️ Deprecated: Use ListStrongAccounts instead. This method uses the legacy API which will be removed in a future version.")
	return s.listSecretsWithFilters("", nil)
}

// Deprecated: Use ListStrongAccounts instead. This method uses the legacy API
// which will be removed in a future version.
// ListBy lists secrets in the Idsec SIA DB by the given filter.
func (s *IdsecSIASecretsDBService) ListBy(filter *dbsecretsmodels.IdsecSIADBSecretsFilter) (*dbsecretsmodels.IdsecSIADBSecretMetadataList, error) {
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
// Enable enables a secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Enable(enableSecret *dbsecretsmodels.IdsecSIADBEnableSecret) error {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy API which will be removed in a future version.")
	if enableSecret.SecretName != "" && enableSecret.SecretID == "" {
		secrets, err := s.ListBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: enableSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		enableSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Enabling db secret by id [%s]", enableSecret.SecretID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(enableSecretURL, enableSecret.SecretID), nil)
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
// Disable disables a secret in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Disable(enableSecret *dbsecretsmodels.IdsecSIADBDisableSecret) error {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy API which will be removed in a future version.")
	if enableSecret.SecretName != "" && enableSecret.SecretID == "" {
		secrets, err := s.ListBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: enableSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return fmt.Errorf("failed to find secret by name: %v", err)
		}
		enableSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Disabling db secret by id [%s]", enableSecret.SecretID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(disableSecretURL, enableSecret.SecretID), nil)
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
// Get retrieves a secret from the Idsec SIA DB by its ID.
func (s *IdsecSIASecretsDBService) Get(getSecret *dbsecretsmodels.IdsecSIADBGetSecret) (*dbsecretsmodels.IdsecSIADBSecretMetadata, error) {
	s.Logger.Warning("⚠️ Deprecated: Use StrongAccount instead. This method uses the legacy API which will be removed in a future version.")
	if getSecret.SecretName != "" && getSecret.SecretID == "" {
		secrets, err := s.ListBy(&dbsecretsmodels.IdsecSIADBSecretsFilter{SecretName: getSecret.SecretName})
		if err != nil || len(secrets.Secrets) == 0 {
			return nil, fmt.Errorf("failed to find secret by name: %v", err)
		}
		getSecret.SecretID = secrets.Secrets[0].SecretID
	}
	s.Logger.Info("Retrieving db secret by id [%s]", getSecret.SecretID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(secretURL, getSecret.SecretID), nil)
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
// Stats retrieves the statistics of secrets in the Idsec SIA DB.
func (s *IdsecSIASecretsDBService) Stats() (*dbsecretsmodels.IdsecSIADBSecretsStats, error) {
	s.Logger.Warning("⚠️ Deprecated: This method uses the legacy APIs which will be removed in a future version.")
	s.Logger.Info("Calculating secrets statistics")
	secretsList, err := s.List()
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
