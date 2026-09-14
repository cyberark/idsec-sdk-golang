package azure

import (
	"context"
	"encoding/json"
	"fmt"

	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API path constants for Azure manual onboarding
const (
	pathManualAddURL             = "/api/azure/manual"
	pathManualEntraGetURL        = "/api/azure/manual/entra/%s"
	pathManualMgmtGroupGetURL    = "/api/azure/manual/mgmtgroup/%s"
	pathManualSubscriptionGetURL = "/api/azure/manual/subscription/%s"
)

// manual returns a ManualClient bound to this service's ISP client and the Azure manual base path.
func (s *IdsecCCEAzureService) manual() *cceinternal.ManualClient {
	return cceinternal.NewManualClient(s.ISPClient(), s.Logger, pathManualAddURL)
}

// tfAddEntra adds an Azure Entra tenant manually.
// After creation, it retrieves the full Entra tenant details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddEntra(input *azuremodels.TfIdsecCCEAzureAddEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Adding Azure Entra tenant with Entra ID [%s]", input.EntraID)

	requestBody, err := cceinternal.StructToMap(input)
	if err != nil {
		return nil, err
	}

	id, err := s.manual().Create(requestBody, cceinternal.DeploymentTypeOrganization)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Entra tenant details with retry
	s.Logger.Info("Retrieving Entra tenant details for ID [%s]", id)
	entra, err := cceinternal.GetWithRetry(s.Logger, "Entra tenant", func() (*azuremodels.TfIdsecCCEAzureEntra, error) {
		return s.tfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{ID: id})
	})
	if err != nil {
		return nil, fmt.Errorf("entra tenant created with ID %s, but failed to fetch details: %w", id, err)
	}

	return entra, nil
}

// tfEntra retrieves Azure Entra tenant details by onboarding ID.
// API: GET /api/azure/manual/entra/{id}
func (s *IdsecCCEAzureService) tfEntra(input *azuremodels.TfIdsecCCEAzureGetEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Getting Azure Entra tenant details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualEntraGetURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
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

// tfUpdateEntra updates an Azure Entra tenant's services.
// It compares the desired services in the input with the current services on the Entra tenant
// and, via the add/update-services endpoint, adds brand-new services and applies partial updates
// (version upgrade and/or a resources change) to already-onboarded services whose desired state
// differs from what is deployed, then removes services that are no longer desired.
//
// Unchanged already-onboarded services are omitted from the request so the (idempotent) endpoint
// leaves them untouched and does not reject the request with a 501 for a service that is not
// update-enabled.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateEntra(input *azuremodels.TfIdsecCCEAzureUpdateEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	s.Logger.Info("Updating Azure Entra tenant [%s]", input.ID)

	// Step 1: Get current Entra tenant service state (names, versions, resources)
	current, err := s.manual().GetCurrentServiceState(fmt.Sprintf(pathManualEntraGetURL, input.ID))
	if err != nil {
		return nil, err
	}

	// Step 2: Use shared update logic to reconcile services
	err = s.manual().UpdateServicesWithReconcile(input.ID, current, input.Services, "entra")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Entra tenant details
	s.Logger.Info("Fetching full details for Entra tenant [%s]", input.ID)
	fullEntra, err := cceinternal.GetWithRetry(s.Logger, "Entra tenant", func() (*azuremodels.TfIdsecCCEAzureEntra, error) {
		return s.tfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{ID: input.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("entra tenant updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullEntra, nil
}

// tfDeleteEntra deletes an Azure Entra tenant.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteEntra(input *azuremodels.TfIdsecCCEAzureDeleteEntra) error {
	s.Logger.Info("Deleting Azure Entra tenant [%s]", input.ID)
	return s.manual().Delete(input.ID)
}

// tfAddManagementGroup adds an Azure Management Group manually.
// After creation, it retrieves the full Management Group details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddManagementGroup(input *azuremodels.TfIdsecCCEAzureAddManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Adding Azure Management Group with ID [%s]", input.ManagementGroupID)

	requestBody, err := cceinternal.StructToMap(input)
	if err != nil {
		return nil, err
	}

	id, err := s.manual().Create(requestBody, cceinternal.DeploymentTypeFolder)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Management Group details with retry
	s.Logger.Info("Retrieving Management Group details for ID [%s]", id)
	mgmtGroup, err := cceinternal.GetWithRetry(s.Logger, "Management Group", func() (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
		return s.tfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: id})
	})
	if err != nil {
		return nil, fmt.Errorf("management group created with ID %s, but failed to fetch details: %w", id, err)
	}

	return mgmtGroup, nil
}

// tfManagementGroup retrieves Azure Management Group details by onboarding ID.
// API: GET /api/azure/manual/mgmtgroup/{id}
func (s *IdsecCCEAzureService) tfManagementGroup(input *azuremodels.TfIdsecCCEAzureGetManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Getting Azure Management Group details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualMgmtGroupGetURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
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

// tfUpdateManagementGroup updates an Azure Management Group's services.
// It compares the desired services in the input with the current services on the Management
// Group and, via the add/update-services endpoint, adds brand-new services and applies partial
// updates (version upgrade and/or a resources change) to already-onboarded services whose desired
// state differs from what is deployed, then removes services that are no longer desired.
//
// Unchanged already-onboarded services are omitted from the request so the (idempotent) endpoint
// leaves them untouched and does not reject the request with a 501 for a service that is not
// update-enabled.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateManagementGroup(input *azuremodels.TfIdsecCCEAzureUpdateManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	s.Logger.Info("Updating Azure Management Group [%s]", input.ID)

	// Step 1: Get current Management Group service state (names, versions, resources)
	current, err := s.manual().GetCurrentServiceState(fmt.Sprintf(pathManualMgmtGroupGetURL, input.ID))
	if err != nil {
		return nil, err
	}

	// Step 2: Use shared update logic to reconcile services
	err = s.manual().UpdateServicesWithReconcile(input.ID, current, input.Services, "management_group")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Management Group details
	s.Logger.Info("Fetching full details for Management Group [%s]", input.ID)
	fullMgmtGroup, err := cceinternal.GetWithRetry(s.Logger, "Management Group", func() (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
		return s.tfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: input.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("management group updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullMgmtGroup, nil
}

// tfDeleteManagementGroup deletes an Azure Management Group.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteManagementGroup(input *azuremodels.TfIdsecCCEAzureDeleteManagementGroup) error {
	s.Logger.Info("Deleting Azure Management Group [%s]", input.ID)
	return s.manual().Delete(input.ID)
}

// tfAddSubscription adds an Azure Subscription manually.
// After creation, it retrieves the full Subscription details with retry logic (3 attempts, 1 second delay).
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) tfAddSubscription(input *azuremodels.TfIdsecCCEAzureAddSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Adding Azure Subscription with ID [%s]", input.SubscriptionID)

	requestBody, err := cceinternal.StructToMap(input)
	if err != nil {
		return nil, err
	}

	id, err := s.manual().Create(requestBody, cceinternal.DeploymentTypeStandalone)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Subscription details with retry
	s.Logger.Info("Retrieving Subscription details for ID [%s]", id)
	subscription, err := cceinternal.GetWithRetry(s.Logger, "Subscription", func() (*azuremodels.TfIdsecCCEAzureSubscription, error) {
		return s.tfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: id})
	})
	if err != nil {
		return nil, fmt.Errorf("subscription created with ID %s, but failed to fetch details: %w", id, err)
	}

	return subscription, nil
}

// tfSubscription retrieves Azure Subscription details by onboarding ID.
// API: GET /api/azure/manual/subscription/{id}
func (s *IdsecCCEAzureService) tfSubscription(input *azuremodels.TfIdsecCCEAzureGetSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Getting Azure Subscription details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathManualSubscriptionGetURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
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

// tfUpdateSubscription updates an Azure Subscription's services.
// It compares the desired services in the input with the current services on the Subscription
// and, via the add/update-services endpoint, adds brand-new services and applies partial updates
// (version upgrade and/or a resources change) to already-onboarded services whose desired state
// differs from what is deployed, then removes services that are no longer desired.
//
// Unchanged already-onboarded services are omitted from the request so the (idempotent) endpoint
// leaves them untouched and does not reject the request with a 501 for a service that is not
// update-enabled.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) tfUpdateSubscription(input *azuremodels.TfIdsecCCEAzureUpdateSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	s.Logger.Info("Updating Azure Subscription [%s]", input.ID)

	// Step 1: Get current Subscription service state (names, versions, resources)
	current, err := s.manual().GetCurrentServiceState(fmt.Sprintf(pathManualSubscriptionGetURL, input.ID))
	if err != nil {
		return nil, err
	}

	// Step 2: Use shared update logic to reconcile services
	err = s.manual().UpdateServicesWithReconcile(input.ID, current, input.Services, "subscription")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Subscription details
	s.Logger.Info("Fetching full details for Subscription [%s]", input.ID)
	fullSubscription, err := cceinternal.GetWithRetry(s.Logger, "Subscription", func() (*azuremodels.TfIdsecCCEAzureSubscription, error) {
		return s.tfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: input.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("subscription updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullSubscription, nil
}

// tfDeleteSubscription deletes an Azure Subscription.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) tfDeleteSubscription(input *azuremodels.TfIdsecCCEAzureDeleteSubscription) error {
	s.Logger.Info("Deleting Azure Subscription [%s]", input.ID)
	return s.manual().Delete(input.ID)
}
