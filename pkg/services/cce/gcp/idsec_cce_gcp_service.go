package gcp

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
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API path constants for GCP operations
const (
	pathIdentityParamsURL  = "/api/gcp/identity-params"
	pathWorkspacesURL      = "/api/gcp/workspaces"
	pathProjectGetURL      = "/api/gcp/manual/project/%s"
	pathOrganizationGetURL = "/api/gcp/manual/organization/%s"
)

// gcpWorkspacesAPIResponse is an internal struct to capture the API response
// which includes pagination information.
type gcpWorkspacesAPIResponse struct {
	Workspaces []ccemodels.TfIdsecCCEWorkspace `json:"workspaces" mapstructure:"workspaces"`
	Page       ccemodels.IdsecCCEPageOutput    `json:"page" mapstructure:"page"`
}

// IdsecCCEGCPService is the implementation of the CCE GCP service.
type IdsecCCEGCPService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecCCEGCPService creates a new instance of IdsecCCEGCPService.
func NewIdsecCCEGCPService(authenticators ...auth.IdsecAuth) (*IdsecCCEGCPService, error) {
	cceGCPService := &IdsecCCEGCPService{}
	var cceGCPServiceInterface services.IdsecService = cceGCPService
	baseService, err := services.NewIdsecBaseService(cceGCPServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, cceinternal.IspServiceName, cceinternal.IspVersion, cceinternal.IspAPIVersion, cceGCPService.refreshCCEGCPAuth)
	if err != nil {
		return nil, err
	}
	cceGCPService.IdsecBaseService = baseService
	cceGCPService.IdsecISPBaseService = ispBaseService
	return cceGCPService, nil
}

func (s *IdsecCCEGCPService) refreshCCEGCPAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// TfProject retrieves GCP Project details by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/gcp/manual/project/{id}
func (s *IdsecCCEGCPService) TfProject(input *gcpmodels.TfIdsecCCEGCPGetProject) (*gcpmodels.TfIdsecCCEGCPProject, error) {
	s.Logger.Info("Getting GCP Project details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathProjectGetURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get Project details")
	}

	var project gcpmodels.TfIdsecCCEGCPProject
	err = json.NewDecoder(response.Body).Decode(&project)
	if err != nil {
		return nil, err
	}

	return &project, nil
}

// TfOrganization retrieves GCP organization details by onboarding ID.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/gcp/manual/organization/{id}
func (s *IdsecCCEGCPService) TfOrganization(input *gcpmodels.TfIdsecCCEGCPGetOrganization) (*gcpmodels.TfIdsecCCEGCPOrganization, error) {
	s.Logger.Info("Getting GCP organization details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathOrganizationGetURL, input.ID)
	response, err := s.ISPClient().Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get organization details")
	}

	var organization gcpmodels.TfIdsecCCEGCPOrganization
	err = json.NewDecoder(response.Body).Decode(&organization)
	if err != nil {
		return nil, err
	}

	return &organization, nil
}

// tfInternalWorkspaces retrieves GCP workspaces with pagination support.
// This is an internal helper function used by the streaming pagination logic.
// API: GET /api/gcp/workspaces
func (s *IdsecCCEGCPService) tfInternalWorkspaces(input *gcpmodels.TfIdsecCCEGCPGetWorkspaces) (*gcpWorkspacesAPIResponse, error) {
	s.Logger.Info("Getting GCP workspaces")

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
	if input.IncludeEmptyWorkspaces {
		params["include_empty_workspaces"] = []string{"true"}
	}
	if input.Services != "" {
		services := strings.Split(input.Services, ",")
		for i, s := range services {
			services[i] = strings.TrimSpace(s)
		}
		params["services"] = services
	}

	response, err := s.ISPClient().Get(context.Background(), pathWorkspacesURL, params)
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

	var workspaces gcpWorkspacesAPIResponse
	err = mapstructure.Decode(workspacesJSON, &workspaces)
	if err != nil {
		return nil, err
	}

	return &workspaces, nil
}

// tfWorkspacesStream retrieves all GCP workspaces by automatically paginating through all pages
// and streams each page through a channel. This follows the established pagination pattern used
// in other services (e.g., AWS/Azure workspaces).
//
// Returns:
//   - pageChannel: Channel that streams gcpWorkspacesAPIResponse pages as they are fetched
//   - errorChannel: Channel that streams errors if any occur during pagination
func (s *IdsecCCEGCPService) tfWorkspacesStream(input *gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform) (<-chan *gcpWorkspacesAPIResponse, <-chan error) {
	const pageSize = 100 // Fixed page size for pagination
	pageChannel := make(chan *gcpWorkspacesAPIResponse)
	errorChannel := make(chan error, 1)

	go func() {
		// Close errorChannel last (LIFO order) so error is readable after pageChannel closes
		defer close(errorChannel)
		defer close(pageChannel)

		// Convert Terraform input to internal input structure
		internalInput := &gcpmodels.TfIdsecCCEGCPGetWorkspaces{
			ParentID:               input.ParentID,
			Services:               input.Services,
			WorkspaceStatus:        input.WorkspaceStatus,
			WorkspaceType:          input.WorkspaceType,
			IncludeEmptyWorkspaces: input.IncludeEmptyWorkspaces,
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

// TfWorkspaces is a Terraform-specific wrapper that retrieves all GCP workspaces by automatically
// paginating through all pages with page_size=100. It takes TfIdsecCCEGCPGetWorkspacesTerraform as input
// (which doesn't include pagination parameters) and returns all found results.
// API: GET /api/gcp/workspaces (called multiple times with pagination)
func (s *IdsecCCEGCPService) TfWorkspaces(input *gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform) (*gcpmodels.TfIdsecCCEGCPWorkspaces, error) {
	s.Logger.Info("Getting all GCP workspaces for Terraform (with pagination)")

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
	return &gcpmodels.TfIdsecCCEGCPWorkspaces{
		Workspaces: allWorkspaces,
	}, nil
}

// TfIdentityParams retrieves GCP workload identity federation parameters for active services.
// ⚠️  DEPRECATED: This function is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// API: GET /api/gcp/identity-params/
func (s *IdsecCCEGCPService) TfIdentityParams(input *gcpmodels.TfIdsecCCEGCPGetIdentityParams) (*gcpmodels.TfIdsecCCEGCPIdentityParams, error) {
	s.Logger.Info("Getting GCP identity parameters")

	response, err := s.ISPClient().Get(context.Background(), pathIdentityParamsURL, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get GCP identity parameters")
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	parsed, err := cceinternal.ParseIdentityParamsResponse(bodyBytes, s.Logger)
	if err != nil {
		return nil, err
	}

	identityParams := &gcpmodels.TfIdsecCCEGCPIdentityParams{
		TenantID:       parsed.TenantID,
		IdentityParams: parsed.IdentityParams,
	}

	s.Logger.Info("Decoded GCP identity parameters response: %+v", identityParams)

	return identityParams, nil
}

// ServiceConfig returns the service configuration for the IdsecCCEGCPService.
func (s *IdsecCCEGCPService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
