package aws

import (
	"context"
	"fmt"
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
// It compares the desired services in the input with the current services on the account and, via the
// add/update-services endpoint, adds brand-new services and applies partial updates to already-onboarded
// services whose version or resources changed, then removes services that are no longer desired.
//
// Unchanged already-onboarded services are omitted from the request so the (idempotent) endpoint leaves
// them untouched and does not reject the request with a 501 for a service that is not update-enabled.
// A resources change on a service that is not update-enabled will surface the endpoint's 501 - which is
// the correct, actionable error - only when that service's resources actually changed.
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

	// Extract current services (names + per-service version + per-service parameters) from raw JSON.
	var currentServiceNames []string
	currentServiceVersions := map[string]string{}
	currentServiceParams := map[string]map[string]interface{}{}
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
		currentServiceVersions = extractCurrentServiceVersions(orgMap)
		currentServiceParams = extractCurrentServiceParameters(orgMap)
	}

	// Step 2: Reconcile services.
	// The account add/update-services endpoint adds a brand-new service and applies partial updates to an
	// already-onboarded service (version upgrade and/or a resources change). It is idempotent (a payload
	// matching the deployed state is a no-op) but rejects (501 FEATURE_NOT_IMPLEMENTED) an already-onboarded
	// service that is not update-enabled - and it validates every already-onboarded service in the request,
	// changed or not. So we send ONLY the services that are new or whose version/resources actually changed;
	// unchanged services (e.g. a service left as-is while another one is updated) must be omitted. Services
	// that are no longer desired are removed separately below.
	desiredServices := make(map[string]bool)
	for _, service := range input.Services {
		desiredServices[service.ServiceName] = true
	}

	// Whether a service is already onboarded is determined by the authoritative "services" name
	// list, NOT by the presence of a version in "services_data": the API may omit the version for
	// an onboarded service, and keying off the version map would then misclassify it as NEW and
	// re-send it, triggering the very 501 we are trying to avoid.
	currentServiceNamesSet := make(map[string]bool, len(currentServiceNames))
	for _, serviceName := range currentServiceNames {
		currentServiceNamesSet[serviceName] = true
	}

	s.Logger.Info("Current account services: %v", currentServiceNames)

	// Determine services to send: brand-new services, already-onboarded services whose desired version
	// differs from the version currently deployed, or already-onboarded services whose user-controlled
	// resources differ from what is currently deployed. (A standalone account has no service_parameters,
	// so the desired parameters are just the service resources.)
	servicesToSend := s.reconcileDesiredServices(input.Services, currentServiceNamesSet, currentServiceVersions, currentServiceParams, nil)

	// Determine services to remove (present on the account but no longer desired).
	var servicesToRemove []string
	for _, serviceName := range currentServiceNames {
		if !desiredServices[serviceName] {
			servicesToRemove = append(servicesToRemove, serviceName)
			s.Logger.Info("Service '%s' will be REMOVED", serviceName)
		}
	}

	// Step 3: Add new services, push version upgrades, or update CCE version.
	var cceVersionToSend string
	if input.CCEVersion != nil {
		cceVersionToSend = *input.CCEVersion
	}
	s.Logger.Info("Services to add/upgrade: %d, Services to remove: %d, CCE version to send: %q\n", len(servicesToSend), len(servicesToRemove), cceVersionToSend)
	if len(servicesToSend) > 0 || cceVersionToSend != "" {
		s.Logger.Info("Sending %d service(s) to account [%s] (CCE version: %q)", len(servicesToSend), input.ID, cceVersionToSend)
		err = s.TfAddAccountServices(&awsmodels.TfIdsecCCEAWSAddAccountServices{
			ID:         input.ID,
			Services:   servicesToSend,
			CCEVersion: cceVersionToSend,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add/update services: %w", err)
		}
	}

	// Step 4: Remove services that are no longer desired.
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

// extractCurrentServiceVersions builds a map of service name -> currently deployed version from
// the account's "services_data" array. Services without a version entry are simply omitted.
// It is used to decide which already-onboarded services represent a real version upgrade (the
// only in-place change the add/update-services endpoint accepts) versus an unchanged service
// that must be excluded from the request to avoid a 501 FEATURE_NOT_IMPLEMENTED response.
func extractCurrentServiceVersions(accountMap map[string]interface{}) map[string]string {
	versions := map[string]string{}
	servicesDataRaw, exists := accountMap["services_data"]
	if !exists {
		return versions
	}
	servicesDataList, ok := servicesDataRaw.([]interface{})
	if !ok {
		return versions
	}
	for _, svcData := range servicesDataList {
		svcMap, ok := svcData.(map[string]interface{})
		if !ok {
			continue
		}
		name, hasName := svcMap["name"].(string)
		version, hasVersion := svcMap["version"].(string)
		if hasName && hasVersion {
			versions[name] = version
		}
	}
	return versions
}

// extractCurrentServiceParameters builds a map of service name -> currently deployed parameters from the
// onboarding's "parameters" object (keyed by service name). The API returns each service's stored parameters
// (user resources merged with terraform service_parameters, e.g. secrets_hub's SecretsManagerRegions),
// snake_cased on read. It is used to detect a real parameter change on an already-onboarded service: the
// org add/update-services endpoint applies such partial updates, but rejects (501 FEATURE_NOT_IMPLEMENTED)
// an already-onboarded service that is not update-enabled, so only genuinely-changed services must be sent.
func extractCurrentServiceParameters(accountMap map[string]interface{}) map[string]map[string]interface{} {
	params := map[string]map[string]interface{}{}
	raw, exists := accountMap["parameters"]
	if !exists {
		return params
	}
	perService, ok := raw.(map[string]interface{})
	if !ok {
		return params
	}
	for name, val := range perService {
		if svcParams, ok := val.(map[string]interface{}); ok {
			params[name] = svcParams
		}
	}
	return params
}

// reconcileDesiredServices determines which desired services must be sent to the account/organization
// add-services endpoint: brand-new services (not yet onboarded), already-onboarded services whose desired
// version differs from what is currently deployed, and already-onboarded services whose user-controlled
// parameters (resources merged with any terraform service_parameters) changed. Unchanged services are
// omitted so we never re-send an already-onboarded service that isn't update-enabled (which the API rejects
// with 501 FEATURE_NOT_IMPLEMENTED).
//
// desiredServiceParameters is the terraform service_parameters map to merge into each desired service's
// resources (pass nil for a standalone account, which has no service_parameters). This is the only thing
// that differs between the account (TfUpdateAccount) and organization (tfUpdateOrganization) update paths,
// which is why they share this helper.
func (s *IdsecCCEAWSService) reconcileDesiredServices(
	desiredServices []ccemodels.IdsecCCEServiceInput,
	currentServiceNamesSet map[string]bool,
	currentServiceVersions map[string]string,
	currentServiceParams map[string]map[string]interface{},
	desiredServiceParameters map[string]map[string]interface{},
) []ccemodels.IdsecCCEServiceInput {
	servicesToSend := make([]ccemodels.IdsecCCEServiceInput, 0)
	for _, service := range desiredServices {
		currentVersion := currentServiceVersions[service.ServiceName]
		desiredParams := mergedDesiredServiceParams(service, desiredServiceParameters)
		switch {
		case !currentServiceNamesSet[service.ServiceName]:
			servicesToSend = append(servicesToSend, service)
			s.Logger.Info("Service '%s' is NEW and will be ADDED", service.ServiceName)
		case service.Version != "" && service.Version != currentVersion:
			servicesToSend = append(servicesToSend, service)
			s.Logger.Info("Service '%s' version changed (%s -> %s) and will be UPGRADED", service.ServiceName, currentVersion, service.Version)
		case cceinternal.ServiceParamsChanged(desiredParams, currentServiceParams[service.ServiceName]):
			servicesToSend = append(servicesToSend, service)
			s.Logger.Info("Service '%s' parameters changed and will be UPDATED", service.ServiceName)
		default:
			s.Logger.Info("Service '%s' is unchanged (version %s), skipping to avoid an unsupported update request", service.ServiceName, currentVersion)
		}
	}
	return servicesToSend
}

// mergedDesiredServiceParams returns the user-controlled parameters for a desired service: its per-service
// resources merged with any terraform service_parameters keyed by that service name. This mirrors how the
// API stores parameters (resources + service_parameters together), so the result can be compared against
// extractCurrentServiceParameters to decide whether the service actually changed.
//
// serviceParameters is optional. When there are no service_parameters for this service - either because the
// caller has none at all (the standalone account path: TfIdsecCCEAWSUpdateAccount has no ServiceParameters
// field) or simply none for this particular service - there is nothing to merge and the service's resources
// are the desired parameters. In that case service.Resources is returned as-is (no throwaway copy). The
// result is only ever read by callers (cceinternal.ServiceParamsChanged), so this aliasing is safe; do not
// mutate it.
func mergedDesiredServiceParams(service ccemodels.IdsecCCEServiceInput,
	serviceParameters map[string]map[string]interface{}) map[string]interface{} {
	extraParams := serviceParameters[service.ServiceName]
	if len(extraParams) == 0 {
		return service.Resources
	}
	merged := make(map[string]interface{}, len(service.Resources)+len(extraParams))
	for key, value := range service.Resources {
		merged[key] = value
	}
	for key, value := range extraParams {
		merged[key] = value
	}
	return merged
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
	s.Logger.Info("Account has %d services %v: %d fully deployed %v, %d waiting for deployment %v",
		len(details.CurrentServiceNames), details.CurrentServiceNames,
		len(details.CurrentFullyDeployedServices), details.CurrentFullyDeployedServices,
		len(details.ServicesWaitingForDeployment), details.ServicesWaitingForDeployment)
	return details, nil
}

// determineServicesToAddWithStatus returns the desired services to send to the organization
// add-account endpoint: the ones the account does not have yet, plus the already-onboarded ones
// whose user-controlled parameters changed since the last apply. An onboarded service that did not
// change is always dropped, because the endpoint reads it as an update and the API rejects the whole
// request with 501 FEATURE_NOT_IMPLEMENTED unless the tenant has the update feature flag on - so one
// unchanged service riding along fails an otherwise legal add.
//
// The change is measured against Terraform's prior state, not against what the API reports. GET
// account resolves an org member to its parent organization's onboarding and returns the
// organization's parameters as the account's, while services_data entries carry no resources at all,
// so the API describes management-account roles while Terraform holds the member account's - a diff
// against it reports a change on every apply. Prior state is also the more accurate question to ask:
// it compares against what this module last sent.
//
// Appearing in the account's service list is not the same as being onboarded. For a programmatic or
// terraform_provider organization, the periodic scan writes a "Waiting for deployment" row for every
// one of the organization's products onto each newly discovered member account, before anyone asks
// for them. The backend does not treat those as existing: it partitions the request against the
// account's stored resources document, and only that partition goes through the upgrade gate. So a
// waiting service this module has never sent is new on both sides and must be sent, or it sits in the
// account's list forever while never deploying.
//
// Without prior state for a service that is already deployed (an import, or state predating this
// field) there is nothing to compare, so it is left alone rather than re-sent on a guess.
//
// This is Step 2 of the TfUpdateOrganizationAccount flow.
func (s *IdsecCCEAWSService) determineServicesToAddWithStatus(
	currentServiceNames []string,
	servicesWaitingForDeployment []string,
	desiredServices []ccemodels.IdsecCCEServiceInput,
	desiredServiceParameters map[string]map[string]interface{},
	previousServices []ccemodels.IdsecCCEServiceInput,
	previousServiceParameters map[string]map[string]interface{},
) []ccemodels.IdsecCCEServiceInput {
	currentServicesMap := make(map[string]bool, len(currentServiceNames))
	for _, serviceName := range currentServiceNames {
		currentServicesMap[serviceName] = true
	}

	waitingForDeployment := make(map[string]bool, len(servicesWaitingForDeployment))
	for _, serviceName := range servicesWaitingForDeployment {
		waitingForDeployment[serviceName] = true
	}

	previousByName := make(map[string]ccemodels.IdsecCCEServiceInput, len(previousServices))
	for _, service := range previousServices {
		previousByName[service.ServiceName] = service
	}

	var servicesToSend []ccemodels.IdsecCCEServiceInput
	for _, service := range desiredServices {
		serviceName := service.ServiceName

		if !currentServicesMap[serviceName] {
			servicesToSend = append(servicesToSend, service)
			s.Logger.Info("Service '%s' is NEW and will be ADDED", serviceName)
			continue
		}

		previous, hasPrevious := previousByName[serviceName]
		if !hasPrevious {
			// Never sent by this module. If it is only waiting, the scan listed it rather than anyone
			// onboarding it, and sending it is what starts the deployment.
			if waitingForDeployment[serviceName] {
				servicesToSend = append(servicesToSend, service)
				s.Logger.Info("Service '%s' is listed as waiting for deployment but was never onboarded, and will be ADDED", serviceName)
				continue
			}
			s.Logger.Info("Service '%s' is already onboarded and has no prior state to compare, skipping", serviceName)
			continue
		}

		if serviceParamsUnchangedSinceLastApply(
			mergedDesiredServiceParams(service, desiredServiceParameters),
			mergedDesiredServiceParams(previous, previousServiceParameters),
		) {
			s.Logger.Info("Service '%s' is already onboarded and unchanged, skipping", serviceName)
			continue
		}

		servicesToSend = append(servicesToSend, service)
		s.Logger.Info("Service '%s' parameters changed since the last apply and will be UPDATED", serviceName)
	}

	return servicesToSend
}

// serviceParamsUnchangedSinceLastApply compares a service's parameters against the same service's
// parameters at the last apply. Both sides come from Terraform, so the comparison is symmetric -
// unlike cceinternal.ServiceParamsChanged, which only inspects keys the desired side has because it
// compares against API-shaped values carrying server-managed extras. A removed key is a change here,
// and an absent map is the same as an empty one.
func serviceParamsUnchangedSinceLastApply(desired, previous map[string]interface{}) bool {
	if len(desired) == 0 && len(previous) == 0 {
		return true
	}
	return cceinternal.JSONValuesEqual(desired, previous)
}

// withoutServiceVersions returns a copy of the services with Version cleared.
//
// A member account has no independently settable version: the add-account endpoint derives it from
// the parent organization's products and its ServiceInput schema has no version field at all.
// Terraform still carries a version on each service so that an organization upgrade produces a plan
// diff on the account resource (see determineServicesToAddWithStatus), but that value is state-only
// and must not be sent to the API.
func withoutServiceVersions(services []ccemodels.IdsecCCEServiceInput) []ccemodels.IdsecCCEServiceInput {
	stripped := make([]ccemodels.IdsecCCEServiceInput, len(services))
	for i, service := range services {
		service.Version = ""
		stripped[i] = service
	}
	return stripped
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
		"services":  withoutServiceVersions(servicesToAdd),
		// Explicitly set the onboarding type to terraform_provider so the API enforces that this account was onboarded via Terraform.
		"onboardingType": ccemodels.TerraformProvider,
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
		// Name the services that were sent: a 501 here means the payload looked like an update, and the
		// response body says nothing about which service caused that.
		sentServices := make([]string, 0, len(servicesToAdd))
		for _, service := range servicesToAdd {
			sentServices = append(sentServices, service.ServiceName)
		}
		return fmt.Errorf("%w (services sent: %s)",
			cceinternal.HandleNon2xxResponse(s.Logger, addResponse.StatusCode, addResponse.Body, "failed to add services to organization account"),
			strings.Join(sentServices, ", "))
	}

	s.Logger.Info("Successfully added %d services", len(servicesToAdd))
	return nil
}

// TfUpdateOrganizationAccount updates services on an AWS account that's part of an organization.
// It adds new services to the account and re-sends already-onboarded services in a settled state whose
// user-controlled parameters actually changed, so that in-place resources/parameters changes are applied
// via the endpoint's idempotent resource diff (unchanged services are omitted). Service removal is not
// needed because when a service is removed from the organization, it is automatically removed from all
// accounts in that organization.
// This method follows the same robust pattern as TfAddOrganizationAccountSync with proper error handling and retry logic.
// API: POST /api/aws/programmatic/organization/{id}/account
func (s *IdsecCCEAWSService) TfUpdateOrganizationAccount(input *awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Updating organization account [%s] in organization [%s] with desired services", input.ID, input.ParentOrganizationID)

	// Step 1: Get current account details to determine AWS account ID and service deployment status
	accountDetails, err := s.getAccountDetailsForUpdate(input.ID)
	if err != nil {
		return nil, err
	}

	// Step 2: Determine which services need to be sent - those the account does not have yet, those
	// the scan listed as waiting without anyone onboarding them, and any onboarded service whose
	// parameters changed since the last apply.
	var priorServices []ccemodels.IdsecCCEServiceInput
	var priorServiceParameters map[string]map[string]interface{}
	if prior := input.PriorState(); prior != nil {
		priorServices = prior.Services
		priorServiceParameters = prior.ServiceParameters
	}
	servicesToAdd := s.determineServicesToAddWithStatus(
		accountDetails.CurrentServiceNames,
		accountDetails.ServicesWaitingForDeployment,
		input.Services,
		input.ServiceParameters,
		priorServices,
		priorServiceParameters,
	)

	// Step 3: If nothing to send, skip the API call
	if len(servicesToAdd) == 0 {
		s.Logger.Info("No services to add or re-send, account is already up to date")
		// Still fetch and return current account details for consistency
		return s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
			ID: input.ID,
		})
	}

	// Step 4: Send the new + re-sent services using the organization API endpoint. The
	// endpoint diffs resources server-side and no-ops services that are unchanged.
	s.Logger.Info("Sending %d service(s) to account", len(servicesToAdd))
	err = s.addServicesToOrganizationAccount(
		input.ParentOrganizationID, // Use the org ID passed from Terraform
		accountDetails.AccountID,
		servicesToAdd,
		input.ServiceParameters,
	)
	if err != nil {
		// The payload is chosen from what the account reports it already has, so name that state too:
		// an add rejected as an update means the API considers a service onboarded that the account did
		// not report back to us.
		return nil, fmt.Errorf("%w [account %s reported services %v]",
			err, accountDetails.AccountID, accountDetails.CurrentServiceNames)
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

	accountJSON, err := s.getAccountJSON(input.ID)
	if err != nil {
		return nil, err
	}

	var account awsmodels.TfIdsecCCEAWSAccount
	err = mapstructure.Decode(accountJSON, &account)
	if err != nil {
		return nil, err
	}
	account.ServiceNames = extractServiceNames(accountJSON)

	return &account, nil
}

// TfAccountDatasource retrieves AWS account details including per-service data
// (name, status, version, available versions) by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/aws/programmatic/account/{id}
func (s *IdsecCCEAWSService) TfAccountDatasource(input *awsmodels.TfIdsecCCEAWSGetAccount) (*awsmodels.TfIdsecCCEAWSAccountDatasource, error) {
	s.Logger.Info("Getting AWS Account datasource details for ID [%s]", input.ID)

	accountJSON, err := s.getAccountJSON(input.ID)
	if err != nil {
		return nil, err
	}

	var account awsmodels.TfIdsecCCEAWSAccountDatasource
	err = mapstructure.Decode(accountJSON, &account)
	if err != nil {
		return nil, err
	}
	account.ServiceNames = extractServiceNames(accountJSON)

	// Property values are a bool/string union that mapstructure skips; populate them from the raw JSON.
	if accountMap, ok := accountJSON.(map[string]interface{}); ok {
		if rawServices, ok := accountMap["services_data"].([]interface{}); ok {
			for i := range account.ServicesData {
				if i >= len(rawServices) {
					break
				}
				if rawService, ok := rawServices[i].(map[string]interface{}); ok {
					if err = account.ServicesData[i].Deserialize(rawService); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return &account, nil
}

// getAccountJSON performs the account details GET and returns the snake_case-deserialized JSON body.
func (s *IdsecCCEAWSService) getAccountJSON(id string) (interface{}, error) {
	url := fmt.Sprintf(pathAccountGetOrDeleteURL, id)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get account details")
	}

	return common.DeserializeJSONSnake(response.Body)
}

// extractServiceNames reads the "services" name list from the raw JSON, since ServiceNames has a mapstructure:"-" tag.
func extractServiceNames(accountJSON interface{}) []string {
	var names []string
	if accountMap, ok := accountJSON.(map[string]interface{}); ok {
		if servicesList, ok := accountMap["services"].([]interface{}); ok {
			names = make([]string, 0, len(servicesList))
			for _, svc := range servicesList {
				if svcStr, ok := svc.(string); ok {
					names = append(names, svcStr)
				}
			}
		}
	}
	return names
}

// DeleteAccount deletes an AWS account programmatically.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/aws/programmatic/account/{id}
func (s *IdsecCCEAWSService) TfDeleteAccount(input *awsmodels.TfIdsecCCEAWSDeleteAccount) error {
	s.Logger.Info("Deleting AWS account with ID [%s]", input.ID)

	url := fmt.Sprintf(pathAccountGetOrDeleteURL, input.ID)
	// Explicitly set the onboarding type to terraform_provider so the API enforces that this account was onboarded via Terraform.
	params := map[string][]string{"onboarding_type": {ccemodels.TerraformProvider}}
	response, err := s.ISPClient().Delete(context.Background(), url, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to delete account")
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
		// Explicitly set the onboarding type to terraform_provider so the API enforces that this account was onboarded via Terraform.
		"onboardingType": ccemodels.TerraformProvider,
	}

	// Add cceVersion if provided
	if input.CCEVersion != "" {
		requestBody["cceVersion"] = input.CCEVersion
	}

	response, err := s.ISPClient().Post(context.Background(), url, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add services to account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add services to account")
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
		// Explicitly set the onboarding type to terraform_provider so the API enforces that this account was onboarded via Terraform.
		"onboarding_type": {ccemodels.TerraformProvider},
	}

	s.Logger.Info("Deleting services: %v from account [%s]", input.ServiceNames, input.ID)

	response, err := s.ISPClient().Delete(context.Background(), path, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete services from account: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to delete services from account")
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
