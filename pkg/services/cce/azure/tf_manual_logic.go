package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API path constants for Azure manual onboarding
const (
	pathManualAddURL             = "/api/azure/manual"
	pathManualDeleteURL          = "/api/azure/manual/%s"
	pathManualEntraGetURL        = "/api/azure/manual/entra/%s"
	pathManualMgmtGroupGetURL    = "/api/azure/manual/mgmtgroup/%s"
	pathManualSubscriptionGetURL = "/api/azure/manual/subscription/%s"
	pathManualServicesURL        = "/api/azure/manual/%s/services"
)

const (
	requestKeyDeploymentType   = "deploymentType"
	requestKeyOnboardingType   = "onboardingType"
	deploymentTypeOrganization = "organization"
	deploymentTypeFolder       = "folder"
	deploymentTypeStandalone   = "standalone"
)

// extractServiceNames extracts the list of service names from an entity JSON response.
// This logic is shared across all Azure manual onboarding entities (Entra, Management Group, Subscription).
// It assumes all entities have a "services" field containing an array of service name strings.
func extractServiceNames(entityJSON interface{}) []string {
	var serviceNames []string
	if entityMap, ok := entityJSON.(map[string]interface{}); ok {
		if servicesRaw, exists := entityMap["services"]; exists {
			if servicesList, ok := servicesRaw.([]interface{}); ok {
				for _, svc := range servicesList {
					if svcStr, ok := svc.(string); ok {
						serviceNames = append(serviceNames, svcStr)
					}
				}
			}
		}
	}
	return serviceNames
}

// structToMap converts a struct to map[string]interface{} using JSON marshaling.
// This is a helper function to simplify request body preparation.
func structToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	return result, nil
}

// tfAddEntra adds an Azure Entra tenant manually.
// After creation, it retrieves the full Entra tenant details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddEntra(input *azuremodels.TfIdsecCCEAzureAddEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Adding Azure Entra tenant with Entra ID [%s]", input.EntraID)

	// Convert input to map and add hardcoded deploymentType
	requestBody, err := structToMap(input)
	if err != nil {
		return nil, err
	}
	requestBody[requestKeyDeploymentType] = deploymentTypeOrganization
	requestBody[requestKeyOnboardingType] = ccemodels.TerraformProvider

	response, err := s.client.Post(context.Background(), pathManualAddURL, requestBody)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add Entra tenant")
	}

	var addOutput azuremodels.IdsecCCEAzureAddOutput
	err = json.NewDecoder(response.Body).Decode(&addOutput)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Entra tenant details with retry
	s.Logger.Info("Retrieving Entra tenant details for ID [%s]", addOutput.ID)
	entra, err := s.tfEntraWithRetry(addOutput.ID)
	if err != nil {
		return nil, fmt.Errorf("entra tenant created with ID %s, but failed to fetch details: %w", addOutput.ID, err)
	}

	return entra, nil
}

// tfEntra retrieves Azure Entra tenant details by onboarding ID.
// API: GET /api/azure/manual/entra/{id}
func (s *IdsecCCEAzureService) tfEntra(input *azuremodels.TfIdsecCCEAzureGetEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Getting Azure Entra tenant details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualEntraGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Entra tenant details")
	}

	var entra azuremodels.TfIdsecCCEAzureEntra
	err = json.NewDecoder(response.Body).Decode(&entra)
	if err != nil {
		return nil, err
	}

	return &entra, nil
}

// tfEntraWithRetry retrieves an Entra tenant with retry logic.
// It attempts to fetch the Entra tenant up to 3 times with 1 second delay between attempts.
func (s *IdsecCCEAzureService) tfEntraWithRetry(entraID string) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	var entra *azuremodels.TfIdsecCCEAzureEntra
	err := common.RetryCall(func() error {
		ent, getErr := s.tfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{ID: entraID})
		if getErr != nil {
			return getErr
		}
		entra = ent
		return nil
	}, cceinternal.DefaultMaxRequestRetries, cceinternal.DefaultRetryDelaySeconds, nil, cceinternal.DefaultRetryBackoffMultiplier, 0, func(err error, delay int) {
		s.Logger.Info("Retrying to get Entra tenant in %d seconds: %v", delay, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Entra tenant: %w", err)
	}

	return entra, nil
}

// tfUpdateEntra updates an Azure Entra tenant's services.
// Compares the desired services in the input with the current services on the Entra tenant,
// then adds new services and removes services that are no longer desired.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateEntra(input *azuremodels.TfIdsecCCEAzureUpdateEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Updating Azure Entra tenant [%s]", input.ID)

	// Step 1: Get current Entra tenant details to determine existing services
	url := fmt.Sprintf(pathManualEntraGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Entra tenant details: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Entra tenant details")
	}

	entraJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Entra tenant response: %w", err)
	}

	// Extract current services from raw JSON
	currentServiceNames := extractServiceNames(entraJSON)

	// Step 2: Use shared update logic to reconcile services
	err = s.updateManualServices(input.ID, currentServiceNames, input.Services, "entra")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Entra tenant details
	s.Logger.Info("Fetching full details for Entra tenant [%s]", input.ID)
	fullEntra, err := s.tfEntraWithRetry(input.ID)
	if err != nil {
		return nil, fmt.Errorf("entra tenant updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullEntra, nil
}

// tfDeleteEntra deletes an Azure Entra tenant.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteEntra(input *azuremodels.TfIdsecCCEAzureDeleteEntra) error {
	s.Logger.Info("Deleting Azure Entra tenant [%s]", input.ID)
	return s.deleteManual(input.ID)
}

// tfAddManagementGroup adds an Azure Management Group manually.
// After creation, it retrieves the full Management Group details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddManagementGroup(input *azuremodels.TfIdsecCCEAzureAddManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Adding Azure Management Group with ID [%s]", input.ManagementGroupID)

	// Convert input to map and add hardcoded deploymentType
	requestBody, err := structToMap(input)
	if err != nil {
		return nil, err
	}
	requestBody[requestKeyDeploymentType] = deploymentTypeFolder
	requestBody[requestKeyOnboardingType] = ccemodels.TerraformProvider

	response, err := s.client.Post(context.Background(), pathManualAddURL, requestBody)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add Management Group")
	}

	var addOutput azuremodels.IdsecCCEAzureAddOutput
	err = json.NewDecoder(response.Body).Decode(&addOutput)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Management Group details with retry
	s.Logger.Info("Retrieving Management Group details for ID [%s]", addOutput.ID)
	mgmtGroup, err := s.tfManagementGroupWithRetry(addOutput.ID)
	if err != nil {
		return nil, fmt.Errorf("management group created with ID %s, but failed to fetch details: %w", addOutput.ID, err)
	}

	return mgmtGroup, nil
}

// tfManagementGroup retrieves Azure Management Group details by onboarding ID.
// API: GET /api/azure/manual/mgmtgroup/{id}
func (s *IdsecCCEAzureService) tfManagementGroup(input *azuremodels.TfIdsecCCEAzureGetManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Getting Azure Management Group details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualMgmtGroupGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Management Group details")
	}

	var mgmtGroup azuremodels.TfIdsecCCEAzureManagementGroup
	err = json.NewDecoder(response.Body).Decode(&mgmtGroup)
	if err != nil {
		return nil, err
	}

	return &mgmtGroup, nil
}

// tfManagementGroupWithRetry retrieves a Management Group with retry logic.
// It attempts to fetch the Management Group up to 3 times with 1 second delay between attempts.
func (s *IdsecCCEAzureService) tfManagementGroupWithRetry(mgmtGroupID string) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	var mgmtGroup *azuremodels.TfIdsecCCEAzureManagementGroup
	err := common.RetryCall(func() error {
		mg, getErr := s.tfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: mgmtGroupID})
		if getErr != nil {
			return getErr
		}
		mgmtGroup = mg
		return nil
	}, cceinternal.DefaultMaxRequestRetries, cceinternal.DefaultRetryDelaySeconds, nil, cceinternal.DefaultRetryBackoffMultiplier, 0, func(err error, delay int) {
		s.Logger.Info("Retrying to get Management Group in %d seconds: %v", delay, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Management Group: %w", err)
	}

	return mgmtGroup, nil
}

// tfUpdateManagementGroup updates an Azure Management Group's services.
// Compares the desired services in the input with the current services on the Management Group,
// then adds new services and removes services that are no longer desired.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateManagementGroup(input *azuremodels.TfIdsecCCEAzureUpdateManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Updating Azure Management Group [%s]", input.ID)

	// Step 1: Get current Management Group details to determine existing services
	url := fmt.Sprintf(pathManualMgmtGroupGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Management Group details: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Management Group details")
	}

	mgmtGroupJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Management Group response: %w", err)
	}

	// Extract current services from raw JSON
	currentServiceNames := extractServiceNames(mgmtGroupJSON)

	// Step 2: Use shared update logic to reconcile services
	err = s.updateManualServices(input.ID, currentServiceNames, input.Services, "management_group")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Management Group details
	s.Logger.Info("Fetching full details for Management Group [%s]", input.ID)
	fullMgmtGroup, err := s.tfManagementGroupWithRetry(input.ID)
	if err != nil {
		return nil, fmt.Errorf("management group updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullMgmtGroup, nil
}

// tfDeleteManagementGroup deletes an Azure Management Group.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteManagementGroup(input *azuremodels.TfIdsecCCEAzureDeleteManagementGroup) error {
	s.Logger.Info("Deleting Azure Management Group [%s]", input.ID)
	return s.deleteManual(input.ID)
}

// tfAddSubscription adds an Azure Subscription manually.
// After creation, it retrieves the full Subscription details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddSubscription(input *azuremodels.TfIdsecCCEAzureAddSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Adding Azure Subscription with ID [%s]", input.SubscriptionID)

	// Convert input to map and add hardcoded deploymentType
	requestBody, err := structToMap(input)
	if err != nil {
		return nil, err
	}
	requestBody[requestKeyDeploymentType] = deploymentTypeStandalone
	requestBody[requestKeyOnboardingType] = ccemodels.TerraformProvider

	response, err := s.client.Post(context.Background(), pathManualAddURL, requestBody)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add Subscription")
	}

	var addOutput azuremodels.IdsecCCEAzureAddOutput
	err = json.NewDecoder(response.Body).Decode(&addOutput)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Subscription details with retry
	s.Logger.Info("Retrieving Subscription details for ID [%s]", addOutput.ID)
	subscription, err := s.tfSubscriptionWithRetry(addOutput.ID)
	if err != nil {
		return nil, fmt.Errorf("subscription created with ID %s, but failed to fetch details: %w", addOutput.ID, err)
	}

	return subscription, nil
}

// tfSubscription retrieves Azure Subscription details by onboarding ID.
// API: GET /api/azure/manual/subscription/{id}
func (s *IdsecCCEAzureService) tfSubscription(input *azuremodels.TfIdsecCCEAzureGetSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Getting Azure Subscription details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualSubscriptionGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Subscription details")
	}

	var subscription azuremodels.TfIdsecCCEAzureSubscription
	err = json.NewDecoder(response.Body).Decode(&subscription)
	if err != nil {
		return nil, err
	}

	return &subscription, nil
}

// tfSubscriptionWithRetry retrieves a Subscription with retry logic.
// It attempts to fetch the Subscription up to 3 times with 1 second delay between attempts.
func (s *IdsecCCEAzureService) tfSubscriptionWithRetry(subscriptionID string) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	var subscription *azuremodels.TfIdsecCCEAzureSubscription
	err := common.RetryCall(func() error {
		sub, getErr := s.tfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: subscriptionID})
		if getErr != nil {
			return getErr
		}
		subscription = sub
		return nil
	}, cceinternal.DefaultMaxRequestRetries, cceinternal.DefaultRetryDelaySeconds, nil, cceinternal.DefaultRetryBackoffMultiplier, 0, func(err error, delay int) {
		s.Logger.Info("Retrying to get Subscription in %d seconds: %v", delay, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Subscription: %w", err)
	}

	return subscription, nil
}

// tfUpdateSubscription updates an Azure Subscription's services.
// Compares the desired services in the input with the current services on the Subscription,
// then adds new services and removes services that are no longer desired.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateSubscription(input *azuremodels.TfIdsecCCEAzureUpdateSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Updating Azure Subscription [%s]", input.ID)

	// Step 1: Get current Subscription details to determine existing services
	url := fmt.Sprintf(pathManualSubscriptionGetURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current Subscription details: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Subscription details")
	}

	subscriptionJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Subscription response: %w", err)
	}

	// Extract current services from raw JSON
	currentServiceNames := extractServiceNames(subscriptionJSON)

	// Step 2: Use shared update logic to reconcile services
	err = s.updateManualServices(input.ID, currentServiceNames, input.Services, "subscription")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Subscription details
	s.Logger.Info("Fetching full details for Subscription [%s]", input.ID)
	fullSubscription, err := s.tfSubscriptionWithRetry(input.ID)
	if err != nil {
		return nil, fmt.Errorf("subscription updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullSubscription, nil
}

// tfDeleteSubscription deletes an Azure Subscription.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteSubscription(input *azuremodels.TfIdsecCCEAzureDeleteSubscription) error {
	s.Logger.Info("Deleting Azure Subscription [%s]", input.ID)
	return s.deleteManual(input.ID)
}

// updateManualServices updates services for an Azure manual onboarding by reconciling service changes.
// Compares the desired services in the input with the current services on the entity,
// then adds new services and removes services that are no longer desired.
func (s *IdsecCCEAzureService) updateManualServices(id string, currentServiceNames []string, desiredServices []ccemodels.IdsecCCEServiceInput, resourceType string) error {
	s.Logger.Info("Updating services for Azure %s [%s]", resourceType, id)

	// Step 1: Compare services to determine what to add and what to remove
	// Build maps for efficient lookup
	desiredServicesMap := make(map[string]ccemodels.IdsecCCEServiceInput)
	for _, service := range desiredServices {
		desiredServicesMap[service.ServiceName] = service
	}

	currentServices := make(map[string]bool)
	for _, serviceName := range currentServiceNames {
		currentServices[serviceName] = true
	}

	s.Logger.Info("Current %s services: %v", resourceType, currentServiceNames)
	s.Logger.Info("Desired %s services after update: %v", resourceType, func() []string {
		names := make([]string, 0, len(desiredServicesMap))
		for name := range desiredServicesMap {
			names = append(names, name)
		}
		return names
	}())

	// Determine services to add (in desired but not in current)
	var servicesToAdd []ccemodels.IdsecCCEServiceInput
	for serviceName, service := range desiredServicesMap {
		if !currentServices[serviceName] {
			servicesToAdd = append(servicesToAdd, service)
			s.Logger.Info("Service '%s' will be ADDED", serviceName)
		}
	}

	// Determine services to remove (in current but not in desired)
	var servicesToRemove []string
	for serviceName := range currentServices {
		if _, exists := desiredServicesMap[serviceName]; !exists {
			servicesToRemove = append(servicesToRemove, serviceName)
			s.Logger.Info("Service '%s' will be REMOVED", serviceName)
		}
	}

	s.Logger.Info("Services to add: %d, Services to remove: %d\n", len(servicesToAdd), len(servicesToRemove))

	// Step 2: Add new services if any
	if len(servicesToAdd) > 0 {
		s.Logger.Info("Adding %d services to %s [%s]", len(servicesToAdd), resourceType, id)
		err := s.addManualServices(id, servicesToAdd)
		if err != nil {
			return fmt.Errorf("failed to add services: %w", err)
		}
	}

	// Step 3: Remove services that are no longer desired
	if len(servicesToRemove) > 0 {
		s.Logger.Info("Removing %d services from %s [%s]", len(servicesToRemove), resourceType, id)
		err := s.deleteManualServices(id, servicesToRemove)
		if err != nil {
			return fmt.Errorf("failed to remove services: %w", err)
		}
	}

	return nil
}

// addManualServices adds services to an Azure manual onboarding.
// API: POST /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) addManualServices(id string, services []ccemodels.IdsecCCEServiceInput) error {
	s.Logger.Info("Adding services to Azure manual onboarding [%s]", id)

	url := fmt.Sprintf(pathManualServicesURL, id)
	requestBody := map[string]interface{}{
		"services": services,
	}

	response, err := s.client.Post(context.Background(), url, requestBody)
	if err != nil {
		return err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add services")
	}

	return nil
}

// deleteManualServices removes services from an Azure manual onboarding.
// API: DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) deleteManualServices(id string, serviceNames []string) error {
	s.Logger.Info("Removing services from Azure manual onboarding [%s]", id)

	basePath := fmt.Sprintf(pathManualServicesURL, id)

	// Build query parameters using url.Values to properly encode multiple values with the same key
	// The API expects multiple services_names query params like: services_names=dpa&services_names=epm
	params := map[string][]string{
		"services_names": serviceNames,
	}

	s.Logger.Info("Deleting services: %v from Azure entity [%s]", serviceNames, id)

	response, err := s.client.Delete(context.Background(), basePath, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete services from Azure manual onboarding: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to delete services from Azure manual onboarding: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// deleteManual deletes an Azure manual onboarding.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) deleteManual(id string) error {
	s.Logger.Info("Deleting Azure manual onboarding [%s]", id)

	url := fmt.Sprintf(pathManualDeleteURL, id)
	response, err := s.client.Delete(context.Background(), url, nil, nil)
	if err != nil {
		return err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to delete manual onboarding")
	}

	return nil
}
