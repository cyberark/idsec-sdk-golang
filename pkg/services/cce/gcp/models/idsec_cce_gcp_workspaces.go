package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEGCPGetWorkspacesTerraform is the input for retrieving GCP workspaces for Terraform.
// This struct does not include pagination parameters as pagination is handled automatically.
// OPENAPI-CORRELATION: Input for GET /api/gcp/workspaces
type TfIdsecCCEGCPGetWorkspacesTerraform struct {
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID.
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID"`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (for example, sia,sca)"`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (for example, Completely added,Failed to add)"`
	// WorkspaceType filters workspaces by their type (e.g., "gcp_organization", "gcp_folder", "gcp_project").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (for example, gcp_organization, gcp_folder, gcp_project)"`
	// IncludeEmptyWorkspaces determines whether to include workspaces with no deployed services in the results.
	IncludeEmptyWorkspaces bool `json:"include_empty_workspaces,omitempty" mapstructure:"include_empty_workspaces,omitempty" desc:"Include empty workspaces (workspaces with no services) in the results"`
}

// TfIdsecCCEGCPGetWorkspaces is the input for retrieving GCP workspaces with pagination.
// This is used internally for paginated API calls.
// OPENAPI-CORRELATION: Input for GET /api/gcp/workspaces
type TfIdsecCCEGCPGetWorkspaces struct {
	// Page is the page number to fetch (1-minimum, default: 1).
	Page int `json:"page,omitempty" mapstructure:"page,omitempty" desc:"Page number to fetch (minimum: 1, default: 1)."`
	// PageSize is the number of items per page (default: 1000).
	PageSize int `json:"page_size,omitempty" mapstructure:"page_size,omitempty" desc:"Number of items per page (default: 1000)."`
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID.
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID."`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (for example, sia,sca)."`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (for example, Completely added,Failed to add)."`
	// WorkspaceType filters workspaces by their type (e.g., "gcp_organization", "gcp_folder", "gcp_project").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (for example, gcp_organization, gcp_folder, gcp_project)."`
	// IncludeEmptyWorkspaces determines whether to include workspaces with no deployed services in the results.
	IncludeEmptyWorkspaces bool `json:"include_empty_workspaces,omitempty" mapstructure:"include_empty_workspaces,omitempty" desc:"Include empty workspaces (workspaces with no services) in the results."`
}

// TfIdsecCCEGCPWorkspaces represents the output of retrieving GCP workspaces.
// Note: This struct does NOT include a Page field as all workspaces are returned in a single collection.
// OPENAPI-CORRELATION: GetWorkspacesOutput
type TfIdsecCCEGCPWorkspaces struct {
	// Workspaces is the list of all workspaces retrieved across all pages.
	Workspaces []ccemodels.TfIdsecCCEWorkspace `json:"workspaces" mapstructure:"workspaces" desc:"List of all retrieved workspaces."`
}
