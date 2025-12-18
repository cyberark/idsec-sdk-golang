package vmsecrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"

	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
)

const (
	secretsURL           = "/api/secrets"
	secretURL            = "/api/secrets/%s" // #nosec G101
	defaultAccountDomain = "local"           // Default domain is "local" for secrets when not specified - align with SIA UI behavior
)

// mapToStringHook is a custom decode hook for mapstructure that converts map[string]interface{} to JSON string.
// This is needed because the API returns secret_details as a map, but our models use string for consistency.
func mapToStringHook(from, to reflect.Type, data interface{}) (interface{}, error) {
	// Check if we're converting from map to string
	if from.Kind() == reflect.Map && to.Kind() == reflect.String {
		// Convert map to JSON string
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal map to JSON string: %w", err)
		}
		return string(jsonBytes), nil
	}
	// Return unchanged for other types
	return data, nil
}

// decodeWithMapToStringHook decodes using mapstructure with a custom hook to convert maps to strings.
func decodeWithMapToStringHook(input, output interface{}) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapToStringHook,
		Result:     output,
		TagName:    "mapstructure",
	})
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}

// IdsecSIASecretsVMService is the service for managing vm secrets.
type IdsecSIASecretsVMService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	// For testing purposes - allows mocking ListSecrets
	mockListSecrets func() ([]*vmsecretsmodels.IdsecSIAVMSecret, error)
}

// NewIdsecSIASecretsVMService creates a new instance of IdsecSIASecretsVMService.
func NewIdsecSIASecretsVMService(authenticators ...auth.IdsecAuth) (*IdsecSIASecretsVMService, error) {
	secretsVMService := &IdsecSIASecretsVMService{}
	var secretsVMServiceInterface services.IdsecService = secretsVMService
	baseService, err := services.NewIdsecBaseService(secretsVMServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", secretsVMService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	secretsVMService.client = client
	secretsVMService.ispAuth = ispAuth
	secretsVMService.IdsecBaseService = baseService
	return secretsVMService, nil
}

func (s *IdsecSIASecretsVMService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// AddSecret adds a new secret to the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) AddSecret(addSecret *vmsecretsmodels.IdsecSIAVMAddSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Adding new vm secret")
	switch addSecret.SecretType {
	case "ProvisionerUser":
		if addSecret.ProvisionerUsername == "" || addSecret.ProvisionerPassword == "" || addSecret.SecretName == "" {
			return nil, fmt.Errorf("provisioner username, password, and secret name are required for ProvisionerUser secret type")
		}
	case "PCloudAccount":
		if addSecret.PCloudAccountSafe == "" || addSecret.PCloudAccountName == "" {
			return nil, fmt.Errorf("pcloud account safe and account name are required for PCloudAccount secret type")
		}
	default:
		return nil, fmt.Errorf("invalid secret type: %s", addSecret.SecretType)
	}
	// Parse user-provided SecretDetails string to map[string]interface{}
	var userProvidedDetails map[string]interface{}
	if addSecret.SecretDetails != "" {
		s.Logger.Info("Received SecretDetails: [%s]", addSecret.SecretDetails)
		err := json.Unmarshal([]byte(addSecret.SecretDetails), &userProvidedDetails)
		if err != nil {
			return nil, fmt.Errorf("invalid secret-details JSON: %w", err)
		}
		s.Logger.Info("Parsed SecretDetails: [%+v]", userProvidedDetails)
	} else {
		userProvidedDetails = map[string]interface{}{}
	}

	// Build secret_details with type-specific defaults
	// Start with defaults, then merge user-provided details (user values take precedence)
	secretDetailsMap := map[string]interface{}{
		"certFileName":               "",
		"account_domain":             defaultAccountDomain,
		"ephemeral_domain_user_data": map[string]interface{}{},
	}

	// Merge user-provided details, allowing overrides of defaults
	for key, value := range userProvidedDetails {
		secretDetailsMap[key] = value
	}

	// Determine the secret name
	secretName := addSecret.SecretName
	if addSecret.SecretType == "PCloudAccount" {
		// For PCloudAccount, generate secret name from account_name and safe
		if addSecret.SecretName != "" {
			return nil, fmt.Errorf("PCloudAccount secret name is auto-generated. Do not provide secret-name")
		}
		secretName = fmt.Sprintf("%s_%s", addSecret.PCloudAccountName, addSecret.PCloudAccountSafe)
	}

	addSecretJSON := map[string]interface{}{
		"secret_name": secretName,
		"secret_type": addSecret.SecretType,
		"secret": map[string]interface{}{
			"tenant_encrypted": false,
		},
		"is_active":      !addSecret.IsDisabled,
		"secret_details": secretDetailsMap,
	}
	switch addSecret.SecretType {
	case "ProvisionerUser":
		addSecretJSON["secret"].(map[string]interface{})["secret_data"] = map[string]interface{}{
			"username": addSecret.ProvisionerUsername,
			"password": addSecret.ProvisionerPassword,
		}
	case "PCloudAccount":
		addSecretJSON["secret"].(map[string]interface{})["secret_data"] = map[string]interface{}{
			"safe":         addSecret.PCloudAccountSafe,
			"account_name": addSecret.PCloudAccountName,
		}
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
	var secret vmsecretsmodels.IdsecSIAVMSecret
	err = decodeWithMapToStringHook(secretJSON, &secret)
	if err != nil {
		return nil, err
	}
	// Ensure SecretDetails is properly set (empty JSON object if not provided)
	if secret.SecretDetails == "" {
		secret.SecretDetails = "{}"
	}
	return &secret, nil
}

// ChangeSecret changes an existing secret in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) ChangeSecret(changeSecret *vmsecretsmodels.IdsecSIAVMChangeSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Changing existing vm secret with id [%s]", changeSecret.SecretID)

	// First, fetch the current secret to get its type and details (required for the API)
	currentSecret, err := s.Secret(&vmsecretsmodels.IdsecSIAVMGetSecret{
		SecretID: changeSecret.SecretID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current secret before change: %w", err)
	}

	// Build the change payload - must include secret_type and is_active
	changeSecretJSON := map[string]interface{}{
		"secret_type": currentSecret.SecretType,
		"is_active":   !changeSecret.IsDisabled,
	}

	// Handle secret_details - parse JSON string and merge with existing details
	if changeSecret.SecretDetails != "" {
		s.Logger.Info("Received SecretDetails: [%s]", changeSecret.SecretDetails)
		var userProvidedDetails map[string]interface{}
		err := json.Unmarshal([]byte(changeSecret.SecretDetails), &userProvidedDetails)
		if err != nil {
			return nil, fmt.Errorf("invalid secret-details JSON: %w", err)
		}
		s.Logger.Info("Parsed SecretDetails: [%+v]", userProvidedDetails)

		// Start with existing details and merge user-provided changes
		mergedDetails := make(map[string]interface{})
		if currentSecret.SecretDetails != "" && currentSecret.SecretDetails != "{}" {
			// Parse existing details from string
			var existingDetails map[string]interface{}
			if err := json.Unmarshal([]byte(currentSecret.SecretDetails), &existingDetails); err == nil {
				for k, v := range existingDetails {
					mergedDetails[k] = v
				}
			}
		}
		// Override with user-provided values
		for k, v := range userProvidedDetails {
			mergedDetails[k] = v
		}
		changeSecretJSON["secret_details"] = mergedDetails
	} else if currentSecret.SecretDetails != "" && currentSecret.SecretDetails != "{}" {
		// Preserve existing details if not changing - parse string to map for API
		var existingDetails map[string]interface{}
		if err := json.Unmarshal([]byte(currentSecret.SecretDetails), &existingDetails); err == nil {
			changeSecretJSON["secret_details"] = existingDetails
		}
	}

	if changeSecret.ProvisionerUsername != "" && changeSecret.ProvisionerPassword != "" {
		changeSecretJSON["secret"] = map[string]interface{}{
			"secret_data": map[string]interface{}{
				"username": changeSecret.ProvisionerUsername,
				"password": changeSecret.ProvisionerPassword,
			},
		}
	}
	if changeSecret.PCloudAccountSafe != "" && changeSecret.PCloudAccountName != "" {
		changeSecretJSON["secret"] = map[string]interface{}{
			"secret_data": map[string]interface{}{
				"safe":         changeSecret.PCloudAccountSafe,
				"account_name": changeSecret.PCloudAccountName,
			},
		}
	}
	if changeSecret.SecretName != "" {
		changeSecretJSON["secret_name"] = changeSecret.SecretName
	}

	response, err := s.client.Put(context.Background(), fmt.Sprintf(secretURL, changeSecret.SecretID), changeSecretJSON)
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
		return nil, fmt.Errorf("failed to change secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	// After successful change, fetch the updated secret to return complete and accurate data
	getSecret := &vmsecretsmodels.IdsecSIAVMGetSecret{
		SecretID: changeSecret.SecretID,
	}
	updatedSecret, err := s.Secret(getSecret)
	if err != nil {
		return nil, err
	}

	// Display what fields were changed
	var changedFields []string
	if changeSecret.SecretName != "" && updatedSecret.SecretName != currentSecret.SecretName {
		changedFields = append(changedFields, fmt.Sprintf("secret_name: %s -> %s", currentSecret.SecretName, updatedSecret.SecretName))
	}
	if changeSecret.ProvisionerUsername != "" || changeSecret.ProvisionerPassword != "" {
		changedFields = append(changedFields, "credentials (username/password)")
	}
	if changeSecret.PCloudAccountSafe != "" || changeSecret.PCloudAccountName != "" {
		changedFields = append(changedFields, "pcloud_account (safe/account_name)")
	}
	if changeSecret.SecretDetails != "" {
		changedFields = append(changedFields, "secret_details")
	}

	if len(changedFields) > 0 {
		s.Logger.Info("Secret updated successfully. Changed: %v", changedFields)
	}

	return updatedSecret, nil
}

// DeleteSecret deletes a secret from the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) DeleteSecret(deleteSecret *vmsecretsmodels.IdsecSIAVMDeleteSecret) error {
	s.Logger.Info("Deleting secret [%s]", deleteSecret.SecretID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(secretURL, deleteSecret.SecretID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

func (s *IdsecSIASecretsVMService) listSecretsWithFilter(secretType string, secretDetails map[string]interface{}) ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
	filterJSON := map[string]string{}
	if secretType != "" {
		filterJSON["secret_type"] = secretType
	}
	for key, value := range secretDetails {
		if value != nil {
			filterJSON[key] = fmt.Sprintf("%v", value)
		}
	}
	response, err := s.client.Get(context.Background(), secretsURL, nil)
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
	secretsResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secrets []*vmsecretsmodels.IdsecSIAVMSecret
	err = decodeWithMapToStringHook(secretsResponseJSON, &secrets)
	if err != nil {
		return nil, err
	}
	// Ensure SecretDetails is properly set (empty JSON object if not provided)
	for _, secret := range secrets {
		if secret.SecretDetails == "" {
			secret.SecretDetails = "{}"
		}
	}
	return secrets, nil
}

// ListSecrets lists all secrets in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) ListSecrets() ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
	// Use mock if available (for testing)
	if s.mockListSecrets != nil {
		s.Logger.Warning("Using mock ListSecrets function for testing")
		return s.mockListSecrets()
	}

	s.Logger.Info("Listing all secrets")
	return s.listSecretsWithFilter("", nil)
}

// ListSecretsBy lists secrets in the SIA VM secrets service by filter.
// Fetches all secrets and filters them client-side based on the provided criteria.
func (s *IdsecSIASecretsVMService) ListSecretsBy(filter *vmsecretsmodels.IdsecSIAVMSecretsFilter) ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Listing secrets by filters [%+v]", filter)

	// Validate secret type if specified
	if filter.SecretType != "" {
		validTypes := []string{"ProvisionerUser", "PCloudAccount"}
		isValid := false
		for _, validType := range validTypes {
			if filter.SecretType == validType {
				isValid = true
				break
			}
		}
		if !isValid {
			return nil, fmt.Errorf("invalid secret type '%s'. Valid types are: ProvisionerUser, PCloudAccount", filter.SecretType)
		}
	}

	// Validate IsActive if specified
	if filter.IsActive != "" {
		isActiveLower := strings.ToLower(filter.IsActive)
		if isActiveLower != "true" && isActiveLower != "false" {
			return nil, fmt.Errorf("invalid is-active value '%s'. Valid values are: true, false", filter.IsActive)
		}
	}

	// Validate Name regex pattern if specified
	if filter.Name != "" {
		if _, err := regexp.Compile(filter.Name); err != nil {
			return nil, fmt.Errorf("invalid name regex pattern '%s': %w", filter.Name, err)
		}
	}

	// Validate AccountDomain regex pattern if specified
	if filter.AccountDomain != "" {
		if _, err := regexp.Compile(filter.AccountDomain); err != nil {
			return nil, fmt.Errorf("invalid account-domain regex pattern '%s': %w", filter.AccountDomain, err)
		}
	}

	// Get all secrets first
	secrets, err := s.ListSecrets()
	if err != nil {
		return nil, err
	}

	// Apply client-side filters
	var filteredSecrets []*vmsecretsmodels.IdsecSIAVMSecret

	for _, secret := range secrets {
		// Filter by IsActive if specified
		if filter.IsActive != "" {
			isActiveLower := strings.ToLower(filter.IsActive)
			if isActiveLower == "true" && !secret.IsActive {
				continue
			}
			if isActiveLower == "false" && secret.IsActive {
				continue
			}
		}

		// Filter by SecretType if specified
		if filter.SecretType != "" && secret.SecretType != filter.SecretType {
			continue
		}

		// Filter by Name pattern if specified
		if filter.Name != "" {
			match, err := regexp.MatchString(filter.Name, secret.SecretName)
			if err != nil || !match {
				continue
			}
		}

		// Filter by AccountDomain pattern if specified
		if filter.AccountDomain != "" {
			// Parse SecretDetails to get account_domain
			detailsMap, err := secret.GetSecretDetailsMap()
			if err != nil {
				continue
			}
			accountDomain, ok := detailsMap["account_domain"].(string)
			if !ok {
				continue
			}
			match, err := regexp.MatchString(filter.AccountDomain, accountDomain)
			if err != nil || !match {
				continue
			}
		}

		// Secret passed all filters, include it
		filteredSecrets = append(filteredSecrets, secret)
	}

	s.Logger.Info("Filtered %d secrets from %d total", len(filteredSecrets), len(secrets))
	return filteredSecrets, nil
}

// Secret retrieves a specific secret from the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Secret(getSecret *vmsecretsmodels.IdsecSIAVMGetSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Getting secret [%s]", getSecret.SecretID)
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var secret vmsecretsmodels.IdsecSIAVMSecret
	err = decodeWithMapToStringHook(secretJSON, &secret)
	if err != nil {
		return nil, err
	}
	// Ensure SecretDetails is properly set (empty JSON object if not provided)
	if secret.SecretDetails == "" {
		secret.SecretDetails = "{}"
	}
	return &secret, nil
}

// SecretsStats retrieves statistics about secrets in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) SecretsStats() (*vmsecretsmodels.IdsecSIAVMSecretsStats, error) {
	secrets, err := s.ListSecrets()
	if err != nil {
		return nil, err
	}
	var secretsStats vmsecretsmodels.IdsecSIAVMSecretsStats
	secretsStats.SecretsCount = len(secrets)
	secretsStats.SecretsCountByType = make(map[string]int)
	for _, secret := range secrets {
		if secret.IsActive {
			secretsStats.ActiveSecretsCount++
		} else {
			secretsStats.InactiveSecretsCount++
		}
		if _, ok := secretsStats.SecretsCountByType[secret.SecretType]; !ok {
			secretsStats.SecretsCountByType[secret.SecretType] = 0
		}
		secretsStats.SecretsCountByType[secret.SecretType]++
	}
	return &secretsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecSIASecretsVMService.
func (s *IdsecSIASecretsVMService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
