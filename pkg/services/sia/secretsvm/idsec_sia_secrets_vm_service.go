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
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm/models"

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

// idsecSIAVMSecretAPIResponse is used internally for API unmarshaling only.
// The API returns secret_details as a JSON object; it is parsed and flattened into IdsecSIAVMSecret.
type idsecSIAVMSecretAPIResponse struct {
	SecretID      string                               `json:"secret_id" mapstructure:"secret_id"`
	TenantID      string                               `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty"`
	Secret        vmsecretsmodels.IdsecSIAVMSecretData `json:"secret,omitempty" mapstructure:"secret,omitempty"`
	SecretType    string                               `json:"secret_type" mapstructure:"secret_type"`
	SecretDetails string                               `json:"secret_details" mapstructure:"secret_details"`
	IsActive      bool                                 `json:"is_active" mapstructure:"is_active"`
	IsRotatable   bool                                 `json:"is_rotatable" mapstructure:"is_rotatable"`
	CreationTime  string                               `json:"creation_time" mapstructure:"creation_time"`
	LastModified  string                               `json:"last_modified" mapstructure:"last_modified"`
	SecretName    string                               `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty"`
}

// apiResponseToPublic converts an API response struct to the public IdsecSIAVMSecret by copying
// base fields and populating flattened fields from the secret_details JSON.
func (s *IdsecSIASecretsVMService) apiResponseToPublic(api *idsecSIAVMSecretAPIResponse) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	public := &vmsecretsmodels.IdsecSIAVMSecret{
		SecretID:     api.SecretID,
		TenantID:     api.TenantID,
		Secret:       api.Secret,
		SecretType:   api.SecretType,
		IsActive:     api.IsActive,
		IsRotatable:  api.IsRotatable,
		CreationTime: api.CreationTime,
		LastModified: api.LastModified,
		SecretName:   api.SecretName,
	}
	if err := s.populateFromSecretDetailsJSON(api.SecretDetails, public); err != nil {
		return nil, err
	}
	return public, nil
}

// populateFromSecretDetailsJSON parses the secret_details JSON string and populates the flattened
// fields on the public secret struct.
func (s *IdsecSIASecretsVMService) populateFromSecretDetailsJSON(secretDetails string, public *vmsecretsmodels.IdsecSIAVMSecret) error {
	if secretDetails == "" {
		return nil
	}
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(secretDetails), &details); err != nil {
		return fmt.Errorf("failed to parse secret_details: %w", err)
	}
	if accountDomain, ok := details["account_domain"].(string); ok {
		public.AccountDomain = accountDomain
	}
	if ephemeralData, ok := details["ephemeral_domain_user_data"].(map[string]interface{}); ok {
		if len(ephemeralData) > 0 {
			enabled := true
			public.EnableEphemeralDomainUserCreation = &enabled
		}
		if dcData, ok := ephemeralData["domain_controller"].(map[string]interface{}); ok {
			if name, ok := dcData["domain_controller_name"].(string); ok {
				public.DomainControllerName = name
			}
			if netbios, ok := dcData["domain_controller_netbios"].(string); ok {
				public.DomainControllerNetbios = netbios
			}
			if useLdaps, ok := dcData["domain_controller_use_ldaps"].(bool); ok {
				public.DomainControllerUseLdaps = &useLdaps
			}
			if enableCertValidation, ok := dcData["domain_controller_enable_certificate_validation"].(bool); ok {
				public.DomainControllerEnableCertificateValidation = &enableCertValidation
			}
			if ldapsCert, ok := dcData["domain_controller_ldaps_certificate"].(string); ok {
				public.DomainControllerLdapsCertificate = ldapsCert
			}
		}
		if location, ok := ephemeralData["ephemeral_domain_user_location"].(string); ok {
			public.EphemeralDomainUserLocation = location
		}
		if winrmData, ok := ephemeralData["winrm_info"].(map[string]interface{}); ok {
			if useHttps, ok := winrmData["use_winrm_for_https"].(bool); ok {
				public.UseWinrmForHTTPS = &useHttps
			}
			if enableCertValidation, ok := winrmData["winrm_enable_certificate_validation"].(bool); ok {
				public.WinrmEnableCertificateValidation = &enableCertValidation
			}
			if cert, ok := winrmData["winrm_certificate"].(string); ok {
				public.WinrmCertificate = cert
			}
		}
	}
	if public.Secret.SecretData != nil {
		if secretDataMap, ok := public.Secret.SecretData.(map[string]interface{}); ok {
			if username, ok := secretDataMap["username"].(string); ok {
				public.ProvisionerUsername = username
			}
		}
	}
	return nil
}

// IdsecSIASecretsVMService is the service for managing vm secrets.
type IdsecSIASecretsVMService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

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

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", secretsVMService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}

	secretsVMService.IdsecBaseService = baseService
	secretsVMService.IdsecISPBaseService = ispBaseService
	return secretsVMService, nil
}

func (s *IdsecSIASecretsVMService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// Create creates a new secret to the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Create(addSecret *vmsecretsmodels.IdsecSIAVMAddSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
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

	// Build secret_details with type-specific defaults
	accountDomain := addSecret.AccountDomain
	if accountDomain == "" {
		accountDomain = defaultAccountDomain
	}

	// Build ephemeral domain user data only if explicitly enabled
	ephemeralDomainUserData := map[string]interface{}{}
	if addSecret.EnableEphemeralDomainUserCreation != nil && *addSecret.EnableEphemeralDomainUserCreation {
		// Ephemeral domain user creation requires a non-local account domain
		if strings.ToLower(accountDomain) == "local" {
			return nil, fmt.Errorf("enable-ephemeral-domain-user-creation requires account-domain to be set to a non-local domain value")
		}

		// Extract params with defaults applied
		ephemeralParams := vmsecretsmodels.ExtractEphemeralParamsFromAddSecret(addSecret)
		if err := vmsecretsmodels.ValidateEphemeralDomainUserParams(ephemeralParams); err != nil {
			return nil, err
		}

		// Build ephemeral_domain_user_data using params with defaults
		ephemeralDomainUserData = vmsecretsmodels.BuildEphemeralDomainUserDataMap(ephemeralParams)
	}

	secretDetailsMap := map[string]interface{}{
		"account_domain":             accountDomain,
		"ephemeral_domain_user_data": ephemeralDomainUserData,
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
		"is_active":      addSecret.IsActive,
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
	var apiSecret idsecSIAVMSecretAPIResponse
	err = decodeWithMapToStringHook(secretJSON, &apiSecret)
	if err != nil {
		return nil, err
	}
	if apiSecret.SecretDetails == "" {
		apiSecret.SecretDetails = "{}"
	}
	return s.apiResponseToPublic(&apiSecret)
}

// Change changes an existing secret in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Change(changeSecret *vmsecretsmodels.IdsecSIAVMChangeSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Changing existing vm secret with id [%s]", changeSecret.SecretID)

	// First, fetch the current secret to get its type and details (required for the API)
	currentSecret, err := s.Get(&vmsecretsmodels.IdsecSIAVMGetSecret{
		SecretID: changeSecret.SecretID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current secret before change: %w", err)
	}

	// Build the change payload - must include secret_type and is_active
	isActive := currentSecret.IsActive
	if changeSecret.IsActive != nil {
		isActive = *changeSecret.IsActive
	}
	changeSecretJSON := map[string]interface{}{
		"secret_type": currentSecret.SecretType,
		"is_active":   isActive,
	}

	// Handle secret_details - build from current secret's flattened fields and merge with change
	mergedDetails := make(map[string]interface{})

	// Resolve account domain: use provided value, or fall back to existing, or default
	accountDomain := changeSecret.AccountDomain
	if accountDomain == "" {
		if currentSecret.AccountDomain != "" {
			accountDomain = currentSecret.AccountDomain
		} else {
			accountDomain = defaultAccountDomain
		}
	}
	mergedDetails["account_domain"] = accountDomain

	// Get existing ephemeral data from current secret's flattened fields
	existingEphemeralData := vmsecretsmodels.EphemeralDomainUserDataMapFromSecret(currentSecret)

	// Handle ephemeral domain user data
	if strings.ToLower(accountDomain) == "local" {
		// Only error if user explicitly tries to enable ephemeral on local domain
		if changeSecret.EnableEphemeralDomainUserCreation != nil && *changeSecret.EnableEphemeralDomainUserCreation {
			return nil, fmt.Errorf("enable-ephemeral-domain-user-creation requires account-domain to be set to a non-local domain value")
		}
		// Local domain: clear ephemeral data, ignore any ephemeral params
		mergedDetails["ephemeral_domain_user_data"] = map[string]interface{}{}
	} else {
		// Determine if ephemeral is enabled: use user value if provided, otherwise check if existing has data
		var enableEphemeral bool
		if changeSecret.EnableEphemeralDomainUserCreation != nil {
			enableEphemeral = *changeSecret.EnableEphemeralDomainUserCreation
		} else {
			// If not provided, inherit from existing (non-empty ephemeral data means it was enabled)
			enableEphemeral = len(existingEphemeralData) > 0
		}

		if enableEphemeral {
			// Ephemeral enabled: merge user values with existing
			ephemeralParams := vmsecretsmodels.ExtractEphemeralParamsFromChangeSecret(changeSecret, existingEphemeralData)
			if err := vmsecretsmodels.ValidateEphemeralDomainUserParams(ephemeralParams); err != nil {
				return nil, err
			}
			mergedDetails["ephemeral_domain_user_data"] = vmsecretsmodels.BuildEphemeralDomainUserDataMap(ephemeralParams)
		} else {
			// Ephemeral disabled: send empty map
			mergedDetails["ephemeral_domain_user_data"] = map[string]interface{}{}
		}
	}

	if len(mergedDetails) > 0 {
		changeSecretJSON["secret_details"] = mergedDetails
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

	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(secretURL, changeSecret.SecretID), changeSecretJSON)
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
	updatedSecret, err := s.Get(getSecret)
	if err != nil {
		return nil, err
	}

	// Display what fields were changed
	var changedFields []string
	if changeSecret.SecretName != "" && updatedSecret.SecretName != currentSecret.SecretName {
		changedFields = append(changedFields, fmt.Sprintf("secret_name: %s -> %s", currentSecret.SecretName, updatedSecret.SecretName))
	}
	if changeSecret.IsActive != nil && updatedSecret.IsActive != currentSecret.IsActive {
		changedFields = append(changedFields, fmt.Sprintf("is_active: %v -> %v", currentSecret.IsActive, updatedSecret.IsActive))
	}
	if changeSecret.ProvisionerUsername != "" || changeSecret.ProvisionerPassword != "" {
		changedFields = append(changedFields, "credentials (username/password)")
	}
	if changeSecret.PCloudAccountSafe != "" || changeSecret.PCloudAccountName != "" {
		changedFields = append(changedFields, "pcloud_account (safe/account_name)")
	}
	if changeSecret.AccountDomain != "" || changeSecret.EnableEphemeralDomainUserCreation != nil {
		changedFields = append(changedFields, "secret_details")
	}

	if len(changedFields) > 0 {
		s.Logger.Info("Secret updated successfully. Changed: %v", changedFields)
	}

	return updatedSecret, nil
}

// Delete deletes a secret from the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Delete(deleteSecret *vmsecretsmodels.IdsecSIAVMDeleteSecret) error {
	s.Logger.Info("Deleting secret [%s]", deleteSecret.SecretID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(secretURL, deleteSecret.SecretID), nil, nil)
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
	response, err := s.ISPClient().Get(context.Background(), secretsURL, nil)
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
	var apiSecrets []idsecSIAVMSecretAPIResponse
	err = decodeWithMapToStringHook(secretsResponseJSON, &apiSecrets)
	if err != nil {
		return nil, err
	}
	secrets := make([]*vmsecretsmodels.IdsecSIAVMSecret, 0, len(apiSecrets))
	for i := range apiSecrets {
		apiSecret := &apiSecrets[i]
		if apiSecret.SecretDetails == "" {
			apiSecret.SecretDetails = "{}"
		}
		public, err := s.apiResponseToPublic(apiSecret)
		if err != nil {
			s.Logger.Warning("Failed to populate fields from secret_details for secret %s: %v", apiSecret.SecretID, err)
			continue
		}
		secrets = append(secrets, public)
	}
	return secrets, nil
}

// List lists all secrets in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) List() ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
	// Use mock if available (for testing)
	if s.mockListSecrets != nil {
		s.Logger.Warning("Using mock ListSecrets function for testing")
		return s.mockListSecrets()
	}

	s.Logger.Info("Listing all secrets")
	return s.listSecretsWithFilter("", nil)
}

// ListBy lists secrets in the SIA VM secrets service by filter.
// Fetches all secrets and filters them client-side based on the provided criteria.
func (s *IdsecSIASecretsVMService) ListBy(filter *vmsecretsmodels.IdsecSIAVMSecretsFilter) ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
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
	secrets, err := s.List()
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
			match, err := regexp.MatchString(filter.AccountDomain, secret.AccountDomain)
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

// get retrieves a specific secret from the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Get(getSecret *vmsecretsmodels.IdsecSIAVMGetSecret) (*vmsecretsmodels.IdsecSIAVMSecret, error) {
	s.Logger.Info("Getting secret [%s]", getSecret.SecretID)
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
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get secret - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	secretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var apiSecret idsecSIAVMSecretAPIResponse
	err = decodeWithMapToStringHook(secretJSON, &apiSecret)
	if err != nil {
		return nil, err
	}
	if apiSecret.SecretDetails == "" {
		apiSecret.SecretDetails = "{}"
	}
	return s.apiResponseToPublic(&apiSecret)
}

// Stats retrieves statistics about secrets in the SIA VM secrets service.
func (s *IdsecSIASecretsVMService) Stats() (*vmsecretsmodels.IdsecSIAVMSecretsStats, error) {
	secrets, err := s.List()
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
