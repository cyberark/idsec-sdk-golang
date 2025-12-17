package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TfIdsecCCEAWSGetWorkspaces is the input for retrieving AWS workspaces.
// OPENAPI-CORRELATION: Input for GET /api/aws/workspaces
type TfIdsecCCEAWSGetWorkspacesTerraform struct {
	// IncludeSuspended indicates whether to include suspended accounts in the results (accounts with suspended services).
	IncludeSuspended bool `json:"include_suspended,omitempty" mapstructure:"include_suspended,omitempty" desc:"Include suspended accounts in results"`
	// IncludeEmptyWorkspaces indicates whether to include empty workspaces in the results (workspaces with no services deployed).
	IncludeEmptyWorkspaces bool `json:"include_empty_workspaces,omitempty" mapstructure:"include_empty_workspaces,omitempty" desc:"Include empty workspaces in results"`
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID (e.g., Organization or organization unit).
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID (Organization or Organization Unit)"`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (e.g., dpa,sca)"`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (e.g., Completely added,Failed to add)"`
	// WorkspaceType filters workspaces by their type (e.g., "aws_organization", "aws_root", "aws_ou", "aws_account").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (e.g., aws_organization, aws_root, aws_ou, aws_account)"`
}

// TfIdsecCCEAWSGetWorkspaces is the input for retrieving AWS workspaces.
// OPENAPI-CORRELATION: Input for GET /api/aws/workspaces
type TfIdsecCCEAWSGetWorkspaces struct {
	// IncludeSuspended indicates whether to include suspended accounts in the results (accounts with suspended services).
	IncludeSuspended bool `json:"include_suspended,omitempty" mapstructure:"include_suspended,omitempty" desc:"Include suspended accounts in results"`
	// IncludeEmptyWorkspaces indicates whether to include empty workspaces in the results (workspaces with no services deployed).
	IncludeEmptyWorkspaces bool `json:"include_empty_workspaces,omitempty" mapstructure:"include_empty_workspaces,omitempty" desc:"Include empty workspaces in results"`
	// Page is the page number to fetch (1-minimum, default: 1).
	Page int `json:"page,omitempty" mapstructure:"page,omitempty" desc:"Page number to fetch (minimum: 1, default: 1)"`
	// PageSize is the number of items per page (default: 1000).
	PageSize int `json:"page_size,omitempty" mapstructure:"page_size,omitempty" desc:"Number of items per page (default: 1000)"`
	// ParentID filters workspaces to only those under the specified parent CCE onboarding ID (e.g., Organization or organization unit).
	ParentID string `json:"parent_id,omitempty" mapstructure:"parent_id,omitempty" desc:"Filter by parent CCE onboarding ID (Organization or Organization Unit)"`
	// Services filters workspaces to only those deployed with the specified services, comma-separated (e.g., "dpa,sca").
	Services string `json:"services,omitempty" mapstructure:"services,omitempty" desc:"Filter by services, comma-separated (e.g., dpa,sca)"`
	// WorkspaceStatus filters workspaces by their onboarding status, comma-separated (e.g., "Completely added,Failed to add,Partially added").
	WorkspaceStatus string `json:"workspace_status,omitempty" mapstructure:"workspace_status,omitempty" desc:"Filter by status, comma-separated (e.g., Completely added,Failed to add)"`
	// WorkspaceType filters workspaces by their type (e.g., "aws_organization", "aws_root", "aws_ou", "aws_account").
	WorkspaceType string `json:"workspace_type,omitempty" mapstructure:"workspace_type,omitempty" desc:"Filter by type (e.g., aws_organization, aws_root, aws_ou, aws_account)"`
}

// TfIdsecCCEAWSWorkspaces represents the output of retrieving AWS workspaces.
// OPENAPI-CORRELATION: GetWorkspacesOutput
type TfIdsecCCEAWSWorkspaces struct {
	// Workspaces is the list of workspaces retrieved.
	Workspaces []ccemodels.TfIdsecCCEWorkspace `json:"workspaces" mapstructure:"workspaces" desc:"List of retrieved workspaces"`
	// Page contains pagination information for the results.
	Page ccemodels.IdsecCCEPageOutput `json:"page" mapstructure:"page" desc:"Pagination information for the results"`
}
