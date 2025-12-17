package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API path constants for Azure general operations
const (
	pathWorkspacesURL     = "/api/azure/workspaces"
	pathIdentityParamsURL = "/api/azure/identity-params"
)

// azureWorkspacesAPIResponse is an internal struct to capture the API response
// which includes pagination information.
type azureWorkspacesAPIResponse struct {
	Workspaces []ccemodels.TfIdsecCCEWorkspace `json:"workspaces" mapstructure:"workspaces"`
	Page       ccemodels.IdsecCCEPageOutput    `json:"page" mapstructure:"page"`
}

// IdsecCCEAzureService is the implementation of the CCE Azure service.
type IdsecCCEAzureService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecCCEAzureService creates a new instance of IdsecCCEAzureService.
func NewIdsecCCEAzureService(authenticators ...auth.IdsecAuth) (*IdsecCCEAzureService, error) {
	cceAzureService := &IdsecCCEAzureService{}
	var cceAzureServiceInterface services.IdsecService = cceAzureService
	baseService, err := services.NewIdsecBaseService(cceAzureServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	client, err := isp.FromISPAuth(ispAuth, cceinternal.IspServiceName, cceinternal.IspVersion, cceinternal.IspAPIVersion, cceAzureService.refreshCCEAzureAuth)
	if err != nil {
		return nil, err
	}
	cceAzureService.client = client
	cceAzureService.ispAuth = ispAuth
	cceAzureService.IdsecBaseService = baseService
	return cceAzureService, nil
}

func (s *IdsecCCEAzureService) refreshCCEAzureAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// TfEntra retrieves Azure Entra tenant details by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/azure/manual/entra/{id}
func (s *IdsecCCEAzureService) TfEntra(input *azuremodels.TfIdsecCCEAzureGetEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	return s.tfEntra(input)
}

// TfAddEntra adds an Azure Entra tenant manually.
// After creation, it retrieves the full Entra tenant details with retry logic (3 attempts, 1 second delay).
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) TfAddEntra(input *azuremodels.TfIdsecCCEAzureAddEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	return s.tfAddEntra(input)
}

// TfUpdateEntra updates an Azure Entra tenant's services.
// Compares the desired services in the input with the current services on the Entra tenant,
// then adds new services and removes services that are no longer desired.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) TfUpdateEntra(input *azuremodels.TfIdsecCCEAzureUpdateEntra) (*azuremodels.TfIdsecCCEAzureEntra, error) {
	return s.tfUpdateEntra(input)
}

// TfDeleteEntra deletes an Azure Entra tenant.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) TfDeleteEntra(input *azuremodels.TfIdsecCCEAzureDeleteEntra) error {
	return s.tfDeleteEntra(input)
}

// TfManagementGroup retrieves Azure Management Group details by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/azure/manual/mgmtgroup/{id}
func (s *IdsecCCEAzureService) TfManagementGroup(input *azuremodels.TfIdsecCCEAzureGetManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	return s.tfManagementGroup(input)
}

// TfAddManagementGroup adds an Azure Management Group manually.
// After creation, it retrieves the full Management Group details with retry logic (3 attempts, 1 second delay).
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) TfAddManagementGroup(input *azuremodels.TfIdsecCCEAzureAddManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	return s.tfAddManagementGroup(input)
}

// TfUpdateManagementGroup updates an Azure Management Group's services.
// Compares the desired services in the input with the current services on the Management Group,
// then adds new services and removes services that are no longer desired.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) TfUpdateManagementGroup(input *azuremodels.TfIdsecCCEAzureUpdateManagementGroup) (*azuremodels.TfIdsecCCEAzureManagementGroup, error) {
	return s.tfUpdateManagementGroup(input)
}

// TfDeleteManagementGroup deletes an Azure Management Group.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) TfDeleteManagementGroup(input *azuremodels.TfIdsecCCEAzureDeleteManagementGroup) error {
	return s.tfDeleteManagementGroup(input)
}

// TfSubscription retrieves Azure Subscription details by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/azure/manual/subscription/{id}
func (s *IdsecCCEAzureService) TfSubscription(input *azuremodels.TfIdsecCCEAzureGetSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	return s.tfSubscription(input)
}

// TfAddSubscription adds an Azure Subscription manually.
// After creation, it retrieves the full Subscription details with retry logic (3 attempts, 1 second delay).
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST /api/azure/manual
func (s *IdsecCCEAzureService) TfAddSubscription(input *azuremodels.TfIdsecCCEAzureAddSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	return s.tfAddSubscription(input)
}

// TfUpdateSubscription updates an Azure Subscription's services.
// Compares the desired services in the input with the current services on the Subscription,
// then adds new services and removes services that are no longer desired.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: POST/DELETE /api/azure/manual/{id}/services
func (s *IdsecCCEAzureService) TfUpdateSubscription(input *azuremodels.TfIdsecCCEAzureUpdateSubscription) (*azuremodels.TfIdsecCCEAzureSubscription, error) {
	return s.tfUpdateSubscription(input)
}

// TfDeleteSubscription deletes an Azure Subscription.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: DELETE /api/azure/manual/{id}
func (s *IdsecCCEAzureService) TfDeleteSubscription(input *azuremodels.TfIdsecCCEAzureDeleteSubscription) error {
	return s.tfDeleteSubscription(input)
}

// tfInternalWorkspaces retrieves Azure workspaces with pagination support.
// This is an internal helper function used by the streaming pagination logic.
// API: GET /api/azure/workspaces
func (s *IdsecCCEAzureService) tfInternalWorkspaces(input *azuremodels.TfIdsecCCEAzureGetWorkspaces) (*azureWorkspacesAPIResponse, error) {
	s.Logger.Info("Getting Azure workspaces")

	// Build query parameters with support for multiple values per key
	params := make(map[string][]string)

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

	response, err := s.client.Get(context.Background(), pathWorkspacesURL, params)
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

	var workspaces azureWorkspacesAPIResponse
	err = mapstructure.Decode(workspacesJSON, &workspaces)
	if err != nil {
		return nil, err
	}

	return &workspaces, nil
}

// tfWorkspacesStream retrieves all Azure workspaces by automatically paginating through all pages
// and streams each page through a channel. This follows the established pagination pattern used
// in other services (e.g., Azure workspaces).
//
// Returns:
//   - pageChannel: Channel that streams azureWorkspacesAPIResponse pages as they are fetched
//   - errorChannel: Channel that streams errors if any occur during pagination
func (s *IdsecCCEAzureService) tfWorkspacesStream(input *azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform) (<-chan *azureWorkspacesAPIResponse, <-chan error) {
	const pageSize = 100 // Fixed page size for pagination
	pageChannel := make(chan *azureWorkspacesAPIResponse)
	errorChannel := make(chan error, 1)

	go func() {
		// Close errorChannel last (LIFO order) so error is readable after pageChannel closes
		defer close(errorChannel)
		defer close(pageChannel)

		// Convert Terraform input to internal input structure
		internalInput := &azuremodels.TfIdsecCCEAzureGetWorkspaces{
			ParentID:        input.ParentID,
			Services:        input.Services,
			WorkspaceStatus: input.WorkspaceStatus,
			WorkspaceType:   input.WorkspaceType,
			PageSize:        pageSize,
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

// TfWorkspaces is a Terraform-specific wrapper that retrieves all Azure workspaces by automatically
// paginating through all pages with page_size=100. It takes TfIdsecCCEAzureGetWorkspacesTerraform as input
// (which doesn't include pagination parameters) and returns all found results.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/azure/workspaces (called multiple times with pagination)
func (s *IdsecCCEAzureService) TfWorkspaces(input *azuremodels.TfIdsecCCEAzureGetWorkspacesTerraform) (*azuremodels.TfIdsecCCEAzureWorkspaces, error) {
	s.Logger.Info("Getting all Azure workspaces for Terraform (with pagination)")

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
	return &azuremodels.TfIdsecCCEAzureWorkspaces{
		Workspaces: allWorkspaces,
	}, nil
}

// TfIdentityParams retrieves Azure identity federation parameters for active services.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/azure/identity_params
func (s *IdsecCCEAzureService) TfIdentityParams(input *azuremodels.TfIdsecCCEAzureGetIdentityParams) (*azuremodels.TfIdsecCCEAzureIdentityParams, error) {
	s.Logger.Info("Getting Azure identity parameters")

	response, err := s.client.Get(context.Background(), pathIdentityParamsURL, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get identity parameters")
	}

	// Read the raw response body
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the response as a map (API returns the map directly at root level)
	var paramsMap map[string]azuremodels.IdsecCCEWorkloadFederation
	if err := json.Unmarshal(bodyBytes, &paramsMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity parameters: %w", err)
	}

	// Wrap the map in the struct
	identityParams := &azuremodels.TfIdsecCCEAzureIdentityParams{
		IdentityParams: paramsMap,
	}

	s.Logger.Info("Decoded identity parameters response: %+v", identityParams)

	return identityParams, nil
}

// ServiceConfig returns the service configuration for the IdsecCCEAzureService.
func (s *IdsecCCEAzureService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
