package aws

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API paths
const (
	workspacesURL                  = "/api/aws/workspaces"
	pathOrganizationAddURL         = "/api/aws/programmatic/organization"
	pathOrganizationGetOrDeleteURL = "/api/aws/programmatic/organization/%s"
	pathOrganizationServicesURL    = "/api/aws/programmatic/organization/%s/services"
	pathOrganizationAccountURL     = "/api/aws/programmatic/organization/%s/account"
	pathOrganizationsScanURL       = "/api/aws/organizations/scan"
	pathAccountAddURL              = "/api/aws/programmatic/account"
	pathAccountGetOrDeleteURL      = "/api/aws/programmatic/account/%s"
	pathAccountServicesURL         = "/api/aws/programmatic/account/%s/services"
	pathTenantServiceDetailsURL    = "/api/aws/tenant/service-details"
)

// IdsecCCEAWSService is the implementation of the CCE AWS service.
type IdsecCCEAWSService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCCEAWSService creates a new instance of IdsecCCEAWSService.
func NewIdsecCCEAWSService(authenticators ...auth.IdsecAuth) (*IdsecCCEAWSService, error) {
	cceAWSService := &IdsecCCEAWSService{}
	var cceAWSServiceInterface services.IdsecService = cceAWSService
	baseService, err := services.NewIdsecBaseService(cceAWSServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, cceinternal.IspServiceName, cceinternal.IspVersion, cceinternal.IspAPIVersion, cceAWSService.refreshCCEAWSAuth)
	if err != nil {
		return nil, err
	}
	cceAWSService.IdsecBaseService = baseService
	cceAWSService.IdsecISPBaseService = ispBaseService
	return cceAWSService, nil
}

func (s *IdsecCCEAWSService) refreshCCEAWSAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// TfOrganization retrieves AWS organization details by management account ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) TfOrganization(input *awsmodels.TfIdsecCCEAWSGetOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	return s.tfOrganization(input)
}

// TfOrganizationDatasource retrieves AWS organization details with services information by management account ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) TfOrganizationDatasource(input *awsmodels.TfIdsecCCEAWSGetOrganization) (*awsmodels.TfIdsecCCEAWSOrganizationDatasource, error) {
	return s.tfOrganizationDatasource(input)
}

// TfAddOrganization adds an AWS organization programmatically using the organization's management account.
// After creation, it retrieves the full organization details with retry logic (3 attempts, 1 second delay).
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/aws/programmatic/organization
func (s *IdsecCCEAWSService) TfAddOrganization(input *awsmodels.TfIdsecCCEAWSAddOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	return s.tfAddOrganization(input)
}

// TfDeleteOrganization deletes an AWS organization by its onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) TfDeleteOrganization(input *awsmodels.TfIdsecCCEAWSGetOrganization) error {
	return s.tfDeleteOrganization(input)
}

// TfUpdateOrganization updates an AWS organization programmatically by reconciling service changes.
// Compares the desired services in the input with the current services on the organization,
// then adds new services and removes services that are no longer desired.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
func (s *IdsecCCEAWSService) TfUpdateOrganization(input *awsmodels.TfIdsecCCEAWSUpdateOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	return s.tfUpdateOrganization(input)
}

// Workspaces retrieves AWS organizations and single accounts with optional filtering.
// API: GET /api/aws/workspaces
func (s *IdsecCCEAWSService) tfInternalWorkspaces(input *awsmodels.TfIdsecCCEAWSGetWorkspaces) (*awsmodels.TfIdsecCCEAWSWorkspaces, error) {
	s.Logger.Info("Getting AWS workspaces")

	// Build query parameters with support for multiple values per key
	params := make(map[string][]string)

	if input.IncludeEmptyWorkspaces {
		params["include_empty_workspaces"] = []string{"true"}
	}
	if input.IncludeSuspended {
		params["include_suspended"] = []string{"true"}
	}
	if input.Page > 0 {
		params["page"] = []string{fmt.Sprintf("%d", input.Page)}
	}
	if input.PageSize > 0 {
		params["page_size"] = []string{fmt.Sprintf("%d", input.PageSize)}
	}
	if input.ParentID != "" {
		params["parent_id"] = []string{input.ParentID}
	}
	if input.WorkspaceStatus != "" {
		params["workspace_status"] = []string{input.WorkspaceStatus}
	}
	if input.WorkspaceType != "" {
		params["workspace_type"] = []string{input.WorkspaceType}
	}
	if input.Services != "" {
		// Split comma-separated services into multiple query params: services=dpa&services=sca
		services := strings.Split(input.Services, ",")
		for i, s := range services {
			services[i] = strings.TrimSpace(s)
		}
		params["services"] = services
	}

	response, err := s.ISPClient().Get(context.Background(), workspacesURL, params)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "Failed to get workspaces details")
	}
	workspacesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var workspaces awsmodels.TfIdsecCCEAWSWorkspaces
	err = mapstructure.Decode(workspacesJSON, &workspaces)
	if err != nil {
		return nil, err
	}

	return &workspaces, nil
}

// tfWorkspacesStream retrieves all AWS workspaces by automatically paginating through all pages
// and streams each page through a channel. This follows the established pagination pattern used
// in other services (e.g., listCommonPools in cmgr service).
//
// Returns:
//   - pageChannel: Channel that streams TfIdsecCCEAWSWorkspaces pages as they are fetched
//   - errorChannel: Channel that streams errors if any occur during pagination
func (s *IdsecCCEAWSService) tfWorkspacesStream(input *awsmodels.TfIdsecCCEAWSGetWorkspacesTerraform) (<-chan *awsmodels.TfIdsecCCEAWSWorkspaces, <-chan error) {
	const pageSize = 100 // Fixed page size for pagination
	pageChannel := make(chan *awsmodels.TfIdsecCCEAWSWorkspaces)
	errorChannel := make(chan error, 1)

	go func() {
		// Close errorChannel last (LIFO order) so error is readable after pageChannel closes
		defer close(errorChannel)
		defer close(pageChannel)

		// Convert Terraform input to internal input structure
		internalInput := &awsmodels.TfIdsecCCEAWSGetWorkspaces{
			IncludeEmptyWorkspaces: input.IncludeEmptyWorkspaces,
			IncludeSuspended:       input.IncludeSuspended,
			ParentID:               input.ParentID,
			Services:               input.Services,
			WorkspaceStatus:        input.WorkspaceStatus,
			WorkspaceType:          input.WorkspaceType,
			PageSize:               pageSize,
		}

		pageNumber := 1
		for {
			internalInput.Page = pageNumber
			s.Logger.Info("Fetching workspaces page %d", pageNumber)

			result, err := s.tfInternalWorkspaces(internalInput)
			if err != nil {
				s.Logger.Error("Failed to fetch workspaces page %d: %v", pageNumber, err)
				errorChannel <- fmt.Errorf("failed to fetch workspaces page %d: %w", pageNumber, err)
				return
			}

			// Send page through channel
			pageChannel <- result

			// Check if this is the last page
			if result.Page.IsLastPage {
				s.Logger.Info("Retrieved all workspaces across %d page(s)", pageNumber)
				break
			}

			pageNumber++
		}
	}()

	return pageChannel, errorChannel
}

// WorkspacesTF is a Terraform-specific wrapper that retrieves all AWS workspaces by automatically
// paginating through all pages with page_size=100. It takes IdsecCCEAWSTFGetWorkspaces as input
// (which doesn't include pagination parameters) and returns all found results.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/workspaces (called multiple times with pagination)
func (s *IdsecCCEAWSService) TfWorkspaces(input *awsmodels.TfIdsecCCEAWSGetWorkspacesTerraform) (*awsmodels.TfIdsecCCEAWSWorkspaces, error) {
	s.Logger.Info("Getting all AWS workspaces for Terraform (with pagination)")

	// Use channel-based pagination internally
	pageChannel, errorChannel := s.tfWorkspacesStream(input)

	// Collect all workspaces across all pages for backward compatibility
	var allWorkspaces []ccemodels.TfIdsecCCEWorkspace
	pageCount := 0

	// Collect all pages - this loop exits when pageChannel is closed
	// (pageChannel closes on both success and error via defer in tfWorkspacesStream)
	for page := range pageChannel {
		allWorkspaces = append(allWorkspaces, page.Workspaces...)
		pageCount++
	}

	// After pageChannel closes, check if there was an error
	// errorChannel is buffered (capacity 1), so the error is preserved even after close
	select {
	case err := <-errorChannel:
		if err != nil {
			return nil, err
		}
	default:
		// No error in channel
	}

	s.Logger.Info("Retrieved all %d workspaces across %d page(s)", len(allWorkspaces), pageCount)
	return &awsmodels.TfIdsecCCEAWSWorkspaces{
		Workspaces: allWorkspaces,
		Page: ccemodels.IdsecCCEPageOutput{
			PageNumber:   1, // Representing as a single combined result
			PageSize:     len(allWorkspaces),
			IsLastPage:   true,
			TotalRecords: len(allWorkspaces),
		},
	}, nil
}

// TenantServiceDetails retrieves tenant service details for AWS.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/tenant/service-details
func (s *IdsecCCEAWSService) TfTenantServiceDetails(input *awsmodels.TfIdsecCCEAWSGetTenantServiceDetails) (*awsmodels.TfIdsecCCEAWSTenantServiceDetails, error) {
	s.Logger.Info("Getting AWS tenant service details")

	response, err := s.ISPClient().Get(context.Background(), pathTenantServiceDetailsURL, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get tenant service details")
	}

	tenantServiceDetailsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var tenantServiceDetails awsmodels.TfIdsecCCEAWSTenantServiceDetails
	err = mapstructure.Decode(tenantServiceDetailsJSON, &tenantServiceDetails)
	if err != nil {
		return nil, err
	}

	return &tenantServiceDetails, nil
}

// TfAddAccount adds an AWS account programmatically and returns full account details.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/aws/programmatic/account
func (s *IdsecCCEAWSService) TfAddAccount(input *awsmodels.TfIdsecCCEAWSAddAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Adding AWS account [%s]", input.AccountID)

	// Explicitly set the onboarding type to terraform_provider if not defined
	if input.OnboardingType == nil {
		defaultOnboardingType := ccemodels.TerraformProvider
		input.OnboardingType = &defaultOnboardingType
	}

	// POST to add the account
	response, err := s.ISPClient().Post(context.Background(), pathAccountAddURL, input)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add account")
	}

	responseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var addedAccount awsmodels.TfIdsecCCEAWSAddedAccount
	err = mapstructure.Decode(responseJSON, &addedAccount)
	if err != nil {
		return nil, err
	}

	// Retrieve the full account details
	s.Logger.Info("Retrieving account details for ID [%s]", addedAccount.ID)
	account, err := s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: addedAccount.ID, // the onboarding ID of the added account
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve account after creation: %w", err)
	}

	return account, nil
}

// UpdateAccount updates an AWS account programmatically by reconciling service changes.
// Compares the desired services in the input with the current services on the account,
// then adds new services and removes services that are no longer desired.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
func (s *IdsecCCEAWSService) TfUpdateAccount(input *awsmodels.TfIdsecCCEAWSUpdateAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Updating AWS account [%s]", input.ID)
	// Step 1: Get current account details to determine existing services
	s.Logger.Info("Getting AWS Account details for ID [%s]", input.ID)
	url := fmt.Sprintf(pathAccountGetOrDeleteURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get account details")
	}

	accountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	// Extract current services from raw JSON
	var currentServiceNames []string
	if orgMap, ok := accountJSON.(map[string]interface{}); ok {
		if servicesRaw, exists := orgMap["services"]; exists {
			if servicesList, ok := servicesRaw.([]interface{}); ok {
				for _, svc := range servicesList {
					if svcStr, ok := svc.(string); ok {
						currentServiceNames = append(currentServiceNames, svcStr)
					}
				}
			}
		}
	}

	// Step 2: Compare services to determine what to add and what to remove
	// Build maps for efficient lookup
	desiredServicesMap := make(map[string]ccemodels.IdsecCCEServiceInput)
	for _, service := range input.Services {
		desiredServicesMap[service.ServiceName] = service
	}

	currentServices := make(map[string]bool)
	for _, serviceName := range currentServiceNames {
		currentServices[serviceName] = true
	}

	s.Logger.Info("Current account services: %v", currentServiceNames)

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

	// Step 3: Add new services if any
	s.Logger.Info("Services to add: %d, Services to remove: %d\n", len(servicesToAdd), len(servicesToRemove))
	if len(servicesToAdd) > 0 {
		s.Logger.Info("Adding %d services to account [%s]", len(servicesToAdd), input.ID)
		err = s.TfAddAccountServices(&awsmodels.TfIdsecCCEAWSAddAccountServices{
			ID:       input.ID,
			Services: servicesToAdd,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add services: %w", err)
		}
	}

	// Step 4: Remove services that are no longer desired
	if len(servicesToRemove) > 0 {
		s.Logger.Info("Removing %d services from account [%s]", len(servicesToRemove), input.ID)
		err = s.DeleteAccountServices(&awsmodels.TfIdsecCCEAWSDeleteAccountServices{
			ID:           input.ID,
			ServiceNames: servicesToRemove,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to remove services: %w", err)
		}
	}

	// Step 5: Fetch and return updated account details
	s.Logger.Info("Fetching full details for account [%s]", input.ID)
	fullAccount, err := s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("account created with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullAccount, nil
}

// accountDetailsForUpdate contains the extracted account information needed for updating organization accounts.
type accountDetailsForUpdate struct {
	AccountID                    string   // AWS account ID (e.g., "575625562187")
	CurrentServiceNames          []string // All service names from "services" field
	CurrentFullyDeployedServices []string // Only services with status "Completely added"
	ServicesWaitingForDeployment []string // Only services with status "Waiting for deployment"
}

// parseAccountServices extracts service information from the account JSON response.
// It returns three lists:
// - allServices: all service names from the "services" field (regardless of status)
// - fullyDeployedServices: only services from "services_data" with status "Completely added"
// - waitingForDeployment: only services from "services_data" with status "Waiting for deployment"
func parseAccountServices(accountMap map[string]interface{}) (allServices []string, fullyDeployedServices []string, waitingForDeployment []string) {
	// Get current services (all service names, regardless of status)
	if servicesRaw, exists := accountMap["services"]; exists {
		if servicesList, ok := servicesRaw.([]interface{}); ok {
			for _, svc := range servicesList {
				if svcStr, ok := svc.(string); ok {
					allServices = append(allServices, svcStr)
				}
			}
		}
	}

	// Get services_data to check deployment status
	// Track services with "Completely added" and "Waiting for deployment" statuses
	if servicesDataRaw, exists := accountMap["services_data"]; exists {
		if servicesDataList, ok := servicesDataRaw.([]interface{}); ok {
			for _, svcData := range servicesDataList {
				if svcMap, ok := svcData.(map[string]interface{}); ok {
					name, hasName := svcMap["name"].(string)
					status, hasStatus := svcMap["status"].(string)
					if hasName && hasStatus {
						switch status {
						case "Completely added":
							fullyDeployedServices = append(fullyDeployedServices, name)
						case "Waiting for deployment":
							waitingForDeployment = append(waitingForDeployment, name)
						}
					}
				}
			}
		}
	}

	return allServices, fullyDeployedServices, waitingForDeployment
}

// getAccountDetailsForUpdate fetches current account details and extracts organization ID, account ID, and current services.
// This is Step 1 of the TfUpdateOrganizationAccount flow.
func (s *IdsecCCEAWSService) getAccountDetailsForUpdate(accountOnboardingID string) (*accountDetailsForUpdate, error) {
	s.Logger.Info("Fetching current account details for ID [%s]", accountOnboardingID)
	url := fmt.Sprintf(pathAccountGetOrDeleteURL, accountOnboardingID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current account details: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get account details")
	}

	accountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize account response: %w", err)
	}

	// Extract account ID and current services from raw JSON
	details := &accountDetailsForUpdate{}
	if orgMap, ok := accountJSON.(map[string]interface{}); ok {
		// Get account ID (AWS 12-digit account ID, not the onboarding ID)
		if accID, exists := orgMap["account_id"]; exists {
			if accIDStr, ok := accID.(string); ok {
				details.AccountID = accIDStr
			}
		}

		// Parse services from the account response
		details.CurrentServiceNames, details.CurrentFullyDeployedServices, details.ServicesWaitingForDeployment = parseAccountServices(orgMap)
	}

	// Validate we got the required information
	if details.AccountID == "" {
		return nil, fmt.Errorf("could not determine AWS account ID for onboarding ID [%s]", accountOnboardingID)
	}

	s.Logger.Info("Account ID: [%s]", details.AccountID)
	s.Logger.Info("Account has %d services: %d fully deployed, %d waiting for deployment",
		len(details.CurrentServiceNames), len(details.CurrentFullyDeployedServices), len(details.ServicesWaitingForDeployment))
	return details, nil
}

// determineServicesToAddWithStatus determines which services to add based on their deployment status.
// Only adds services that are either:
// - Completely new (not in currentServiceNames at all)
// - OR have status "Waiting for deployment" (in waitingForDeployment list)
// Services with other statuses (like "In progress", "Failed", etc.) are skipped.
// This is Step 2 of the TfUpdateOrganizationAccount flow.
func (s *IdsecCCEAWSService) determineServicesToAddWithStatus(
	currentServiceNames []string,
	waitingForDeployment []string,
	fullyDeployed []string,
	desiredServices []ccemodels.IdsecCCEServiceInput,
) []ccemodels.IdsecCCEServiceInput {
	// Build maps for efficient lookup
	currentServicesMap := make(map[string]bool)
	for _, serviceName := range currentServiceNames {
		currentServicesMap[serviceName] = true
	}

	waitingMap := make(map[string]bool)
	for _, serviceName := range waitingForDeployment {
		waitingMap[serviceName] = true
	}

	fullyDeployedMap := make(map[string]bool)
	for _, serviceName := range fullyDeployed {
		fullyDeployedMap[serviceName] = true
	}

	// Determine services to add
	var servicesToAdd []ccemodels.IdsecCCEServiceInput
	for _, service := range desiredServices {
		serviceName := service.ServiceName

		// Skip if already fully deployed
		if fullyDeployedMap[serviceName] {
			s.Logger.Info("Service '%s' is already fully deployed (status: 'Completely added'), skipping", serviceName)
			continue
		}

		// Add if completely new (not in current services at all)
		if !currentServicesMap[serviceName] {
			servicesToAdd = append(servicesToAdd, service)
			s.Logger.Info("Service '%s' is NEW and will be ADDED", serviceName)
			continue
		}

		// Add if waiting for deployment
		if waitingMap[serviceName] {
			servicesToAdd = append(servicesToAdd, service)
			s.Logger.Info("Service '%s' is waiting for deployment and will be RE-ADDED", serviceName)
			continue
		}

		// Skip services with other statuses (In progress, Failed, etc.)
		s.Logger.Info("Service '%s' has other status (not 'Completely added' or 'Waiting for deployment'), skipping", serviceName)
	}

	return servicesToAdd
}

// addServicesToOrganizationAccount adds new services to an account using the organization API endpoint.
// This is Step 3 of the TfUpdateOrganizationAccount flow.
func (s *IdsecCCEAWSService) addServicesToOrganizationAccount(
	organizationID string,
	accountID string,
	servicesToAdd []ccemodels.IdsecCCEServiceInput,
	serviceParameters map[string]map[string]interface{},
) error {
	s.Logger.Info("Adding %d new services to organization account [%s] in organization [%s]", len(servicesToAdd), accountID, organizationID)

	// Use the organization API to add services to the account
	requestBody := map[string]interface{}{
		"accountId": accountID,
		"services":  servicesToAdd,
	}

	// Add service parameters if provided
	if len(serviceParameters) > 0 {
		requestBody["serviceParameters"] = serviceParameters
		s.Logger.Info("Including service parameters for services: %v", func() []string {
			keys := make([]string, 0, len(serviceParameters))
			for k := range serviceParameters {
				keys = append(keys, k)
			}
			return keys
		}())
	}

	orgAccountURL := fmt.Sprintf(pathOrganizationAccountURL, organizationID)
	addResponse, err := s.ISPClient().Post(context.Background(), orgAccountURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add services to organization account: %w", err)
	}
	defer cceinternal.CloseResponseBody(addResponse.Body)

	if !cceinternal.IsHTTPSuccess(addResponse.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, addResponse.StatusCode, addResponse.Body, "failed to add services to organization account")
	}

	s.Logger.Info("Successfully added %d services", len(servicesToAdd))
	return nil
}

// TfUpdateOrganizationAccount updates services on an AWS account that's part of an organization.
// It only adds new services to the account. Service removal is not needed because when a service
// is removed from the organization, it is automatically removed from all accounts in that organization.
// This method follows the same robust pattern as TfAddOrganizationAccountSync with proper error handling and retry logic.
// API: POST /api/aws/programmatic/organization/{id}/account
func (s *IdsecCCEAWSService) TfUpdateOrganizationAccount(input *awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Updating organization account [%s] in organization [%s] with desired services", input.ID, input.ParentOrganizationID)

	// Step 1: Get current account details to determine AWS account ID and service deployment status
	accountDetails, err := s.getAccountDetailsForUpdate(input.ID)
	if err != nil {
		return nil, err
	}

	// Step 2: Determine which services need to be added
	// Only add services that are either:
	// - Completely new (not in current services at all)
	// - OR have status "Waiting for deployment"
	// Services with other statuses (like "In progress", "Failed", etc.) are skipped
	servicesToAdd := s.determineServicesToAddWithStatus(
		accountDetails.CurrentServiceNames,
		accountDetails.ServicesWaitingForDeployment,
		accountDetails.CurrentFullyDeployedServices,
		input.Services,
	)

	// Step 3: If no new services to add, skip the API call
	if len(servicesToAdd) == 0 {
		s.Logger.Info("No new services to add, account is already up to date")
		// Still fetch and return current account details for consistency
		return s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
			ID: input.ID,
		})
	}

	// Step 4: Add only the NEW services using the organization API endpoint
	s.Logger.Info("Adding %d new service(s) to account", len(servicesToAdd))
	err = s.addServicesToOrganizationAccount(
		input.ParentOrganizationID, // Use the org ID passed from Terraform
		accountDetails.AccountID,
		servicesToAdd, // Send only NEW services (delta)
		input.ServiceParameters,
	)
	if err != nil {
		return nil, err
	}

	// Step 5: Fetch and return updated account details using existing retry logic
	s.Logger.Info("Fetching full account details for account ID [%s]", input.ID)
	fullAccount, err := s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: input.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("services added successfully but failed to fetch updated account details: %w", err)
	}

	s.Logger.Info("Successfully updated organization account [%s]", input.ID)
	return fullAccount, nil
}

// accountWithRetry wraps the Account() method with retry logic for transient failures.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/programmatic/account/{id}
func (s *IdsecCCEAWSService) accountWithRetry(input *awsmodels.TfIdsecCCEAWSGetAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Getting AWS account details with retry for ID [%s]", input.ID)

	maxRetries := cceinternal.DefaultMaxRequestRetries
	retryDelay := cceinternal.DefaultRequestRetryDelay

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			s.Logger.Info("Retry attempt %d/%d after %v", attempt, maxRetries, retryDelay)
			time.Sleep(retryDelay)
		}

		account, err := s.TfAccount(input)
		if err == nil {
			return account, nil
		}

		lastErr = err

		// Check if error is retryable
		if !cceinternal.IsRetryableError(0, err) {
			s.Logger.Info("Non-retryable error, not retrying: %v", err)
			break
		}

		s.Logger.Info("Retryable error on attempt %d: %v", attempt+1, err)
	}

	return nil, fmt.Errorf("failed to get account details after %d attempts: %w", maxRetries+1, lastErr)
}

// Account retrieves AWS account details by account ID and deserializes union types.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/programmatic/account/{id}
func (s *IdsecCCEAWSService) TfAccount(input *awsmodels.TfIdsecCCEAWSGetAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Getting AWS Account details for ID [%s]", input.ID)
	url := fmt.Sprintf(pathAccountGetOrDeleteURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get account details")
	}

	accountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var account awsmodels.TfIdsecCCEAWSAccount
	err = mapstructure.Decode(accountJSON, &account)
	if err != nil {
		return nil, err
	}

	// Extract ServiceNames from raw JSON since it has mapstructure:"-" tag
	if accountMap, ok := accountJSON.(map[string]interface{}); ok {
		if servicesRaw, exists := accountMap["services"]; exists {
			if servicesList, ok := servicesRaw.([]interface{}); ok {
				account.ServiceNames = make([]string, 0, len(servicesList))
				for _, svc := range servicesList {
					if svcStr, ok := svc.(string); ok {
						account.ServiceNames = append(account.ServiceNames, svcStr)
					}
				}
			}
		}
	}

	return &account, nil
}

// DeleteAccount deletes an AWS account programmatically.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/aws/programmatic/account/{id}
func (s *IdsecCCEAWSService) TfDeleteAccount(input *awsmodels.TfIdsecCCEAWSDeleteAccount) error {
	s.Logger.Info("Deleting AWS account with ID [%s]", input.ID)

	url := fmt.Sprintf(pathAccountGetOrDeleteURL, input.ID)
	response, err := s.ISPClient().Delete(context.Background(), url, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to delete account: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// AddAccountServices adds services to an AWS account programmatically
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/aws/programmatic/account/{id}/services
func (s *IdsecCCEAWSService) TfAddAccountServices(input *awsmodels.TfIdsecCCEAWSAddAccountServices) error {
	s.Logger.Info("Adding services to AWS account [%s]", input.ID)

	url := fmt.Sprintf(pathAccountServicesURL, input.ID)

	// Create request body with services array
	requestBody := map[string]interface{}{
		"services": input.Services,
	}

	response, err := s.ISPClient().Post(context.Background(), url, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add services to account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to add services to account: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// DeleteAccountServices removes services from an AWS account programmatically.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/aws/programmatic/account/{id}/services
func (s *IdsecCCEAWSService) DeleteAccountServices(input *awsmodels.TfIdsecCCEAWSDeleteAccountServices) error {
	s.Logger.Info("Deleting services from AWS account [%s]", input.ID)

	path := fmt.Sprintf(pathAccountServicesURL, input.ID)

	// Build query parameters with multiple values for the same key
	// The API expects: services_names=dpa&services_names=sca
	params := map[string][]string{
		"services_names": input.ServiceNames,
	}

	s.Logger.Info("Deleting services: %v from account [%s]", input.ServiceNames, input.ID)

	response, err := s.ISPClient().Delete(context.Background(), path, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete services from account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to delete services from account: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// ScanOrganization triggers an AWS organization discovery scan.
// API: POST /api/aws/organizations/scan
func (s *IdsecCCEAWSService) ScanOrganization(input *awsmodels.IdsecCCEAWSScanOrganization) (*awsmodels.IdsecCCEAWSScanResult, error) {
	s.Logger.Info("Triggering AWS organization discovery scan")

	response, err := s.ISPClient().Post(context.Background(), pathOrganizationsScanURL, input)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to trigger organization scan")
	}

	// Return empty result on success
	return &awsmodels.IdsecCCEAWSScanResult{}, nil
}

// TfAddOrganizationAccountSync adds an AWS account to an organization with intelligent retry logic.
// If the account is not yet discovered (404), it triggers a scan and retries with configurable intervals.
// Returns the full account details after successful addition.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/aws/programmatic/organization/{id}/account
func (s *IdsecCCEAWSService) TfAddOrganizationAccountSync(input *awsmodels.IdsecCCEAWSAddOrganizationAccountSync) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	return s.tfAddOrganizationAccountSync(input)
}

// ServiceConfig returns the service configuration for the IdsecCCEAWSService.
func (s *IdsecCCEAWSService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
