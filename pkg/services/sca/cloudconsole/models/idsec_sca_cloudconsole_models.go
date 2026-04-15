// Package models provides data structures for SCA cloud-console operations.
package models

// IdsecSCARoleInfo represents the IAM role with which a user is eligible to access a workspace.
//
// Corresponds to the RoleInfo schema in the SCA API spec.
//
// Fields:
//   - ID:   The unique identifier of the role.
//   - Name: The display name of the role.
type IdsecSCARoleInfo struct {
	ID   string `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the role"`
	Name string `json:"name" mapstructure:"name" flag:"name" desc:"The name of the role"`
}

// IdsecSCAEligibleTarget represents a single eligible cloud-console target returned by
// the SCA eligibility API (GET /access/{csp}/eligibility).
//
// Corresponds to the CommonEligibleTarget + CSP-specific allOf schemas in the API spec:
//   - AWSAccountEligibleTarget    (workspaceType: ACCOUNT)
//   - AWSOrgAccountEligibleTarget (workspaceType: ACCOUNT, organizationId present)
//   - GCPEligibleTarget           (workspaceType: PROJECT | FOLDER | GCP_ORGANIZATION)
//   - AzureEligibleTarget         (workspaceType: RESOURCE | RESOURCE_GROUP | SUBSCRIPTION | MANAGEMENT_GROUP | DIRECTORY)
//
// Fields:
//   - WorkspaceID:     The ID of the workspace (required by API).
//   - WorkspaceName:   The display name of the workspace (max 255 chars).
//   - RoleInfo:        The role with which the user is eligible to access the workspace.
//   - OrganizationID:  The ID of the containing organization/tenant (AWS org, GCP org, Azure tenant).
//   - WorkspaceType:   The type of the workspace (enum varies per CSP).
type IdsecSCAEligibleTarget struct {
	WorkspaceID    string           `json:"workspaceId" mapstructure:"workspaceId" flag:"workspace-id" desc:"The ID of the workspace"`
	WorkspaceName  string           `json:"workspaceName,omitempty" mapstructure:"workspaceName" flag:"workspace-name" desc:"The display name of the workspace"`
	RoleInfo       IdsecSCARoleInfo `json:"role" mapstructure:"roleInfo" flag:"role-info" desc:"The role with which you are eligible to access the workspace"`
	OrganizationID string           `json:"organizationId,omitempty" mapstructure:"organizationId" flag:"organization-id" desc:"The ID of the organization or tenant that contains the workspace (AWS org ID | GCP org ID | Azure Entra tenant ID)"`
	WorkspaceType  string           `json:"workspaceType,omitempty" mapstructure:"workspaceType" flag:"workspace-type" desc:"The type of the workspace (AWS: ACCOUNT | GCP: PROJECT, FOLDER, GCP_ORGANIZATION | AZURE: RESOURCE, RESOURCE_GROUP, SUBSCRIPTION, MANAGEMENT_GROUP, DIRECTORY)"`
}

// IdsecSCAListTargetsResponse is the response from GET /access/{csp}/eligibility.
//
// Fields:
//   - Response:  List of eligible cloud-console targets.
//   - Total:     Total number of eligible targets across all pages.
//   - NextToken: Pagination token to retrieve the next page; empty when no more pages.
type IdsecSCAListTargetsResponse struct {
	Response  []IdsecSCAEligibleTarget `json:"response" mapstructure:"response" flag:"response" desc:"The list of targets you are eligible to access"`
	Total     int                      `json:"total" mapstructure:"total" flag:"total" desc:"The total number of targets you are eligible to access"`
	NextToken string                   `json:"nextToken,omitempty" mapstructure:"nextToken" flag:"next-token" desc:"The token for retrieving the next page of results"`
}

// IdsecSCACloudConsoleElevateTarget describes a single workspace-role target for elevation.
//
// WorkspaceID is required. Exactly one of RoleID or RoleName must be provided — not both.
//
// Notes:
//   - The workspace ID for all GCP targets must be the same.
//   - The workspace ID for all Azure targets must be the same.
type IdsecSCACloudConsoleElevateTarget struct {
	WorkspaceID string `json:"workspaceId" mapstructure:"workspaceId" flag:"workspace-id" desc:"The ID of the workspace to which access is being requested. For GCP and Azure, the workspace ID for all targets must be the same."`
	RoleID      string `json:"roleId,omitempty" mapstructure:"roleId,omitempty" flag:"role-id" desc:"The ID of the role with which you're eligible to access the target. Provide either role-id or role-name, but not both."`
	RoleName    string `json:"roleName,omitempty" mapstructure:"roleName,omitempty" flag:"role-name" desc:"The name of the role with which you're eligible to access the target. Provide either role-name or role-id, but not both."`
}

// IdsecSCACloudConsoleElevateRequest is the POST body for POST /access/elevate.
//
// Targets constraints (minItems: 1, maxItems: 5):
//   - Standalone AWS account: max 1 target.
//   - AWS account in an org: max 1 target.
//   - GCP folders/projects (same org, multi-role enabled): max 5; otherwise max 1.
//   - Azure subscriptions/resource groups/resources (same mgmt group, multi-role enabled): max 5; otherwise max 1.
//   - Azure Entra ID (multi-role enabled): max 3; otherwise max 1.
//
// OrganizationID is not relevant for standalone AWS accounts.
type IdsecSCACloudConsoleElevateRequest struct {
	CSP            string                              `json:"csp" mapstructure:"csp" flag:"csp" desc:"The cloud provider that hosts the workspaces for which access is required. Enum: AWS | AZURE | GCP"`
	Targets        []IdsecSCACloudConsoleElevateTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"The targets (workspace + role) for which access is being requested. Min: 1, Max: 5 (exact limit varies by CSP and configuration)"`
	OrganizationID string                              `json:"organizationId,omitempty" mapstructure:"organizationId,omitempty" flag:"organization-id" desc:"The ID of the organization that contains the workspaces. All specified workspaces and roles must be part of this organization. Not relevant for standalone AWS accounts."`
}

// IdsecSCACloudConsoleElevateErrorInfo is present in a result when the user is not
// eligible to access the requested target. When non-nil, AccessCredentials will be empty.
//
// Fields:
//   - Code:        Error code (e.g. "CA1009").
//   - Message:     Short human-readable message.
//   - Description: Detailed explanation of why access was denied.
//   - Link:        URL to the relevant troubleshooting documentation.
type IdsecSCACloudConsoleElevateErrorInfo struct {
	Code        string `json:"code" mapstructure:"code"`
	Message     string `json:"message" mapstructure:"message"`
	Description string `json:"description" mapstructure:"description"`
	Link        string `json:"link,omitempty" mapstructure:"link,omitempty"`
}

// IdsecSCACloudConsoleElevateResult represents one result entry in the elevate response.
//
// On success, AccessCredentials contains a JSON-encoded string (double-encoded) with
// aws_access_key, aws_secret_access_key, and aws_session_token.
// On failure (e.g. user not eligible), ErrorInfo is populated and AccessCredentials is empty.
type IdsecSCACloudConsoleElevateResult struct {
	WorkspaceID       string                                `json:"workspaceId" mapstructure:"workspaceId"`
	RoleID            string                                `json:"roleId,omitempty" mapstructure:"roleId,omitempty"`
	SessionID         string                                `json:"sessionId,omitempty" mapstructure:"sessionId,omitempty"`
	AccessCredentials string                                `json:"accessCredentials,omitempty" mapstructure:"accessCredentials,omitempty"`
	ErrorInfo         *IdsecSCACloudConsoleElevateErrorInfo `json:"errorInfo,omitempty" mapstructure:"errorInfo,omitempty"`
}

// IdsecSCACloudConsoleElevateResponseBody is the inner "response" object in the elevate API reply.
type IdsecSCACloudConsoleElevateResponseBody struct {
	OrganizationID string                              `json:"organizationId" mapstructure:"organizationId"`
	CSP            string                              `json:"csp" mapstructure:"csp"`
	Results        []IdsecSCACloudConsoleElevateResult `json:"results" mapstructure:"results"`
}

// IdsecSCACloudConsoleElevateResponse is the top-level elevate API reply.
type IdsecSCACloudConsoleElevateResponse struct {
	Response IdsecSCACloudConsoleElevateResponseBody `json:"response" mapstructure:"response"`
}

// IdsecSCACloudConsoleElevateActionRequest is the flat CLI schema for
// `idsec exec sca cloud-console elevate`.
//
// Registered in ActionToSchemaMap so the framework generates cobra flags automatically.
// The framework maps "elevate" → Elevate() by naming convention (same as list-targets → ListTargets()).
type IdsecSCACloudConsoleElevateActionRequest struct {
	CSP            string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AWS, AZURE, GCP)"`
	WorkspaceID    string `json:"workspace_id" mapstructure:"workspace_id" validate:"required" flag:"workspace-id" desc:"The ID of the workspace (e.g. AWS account ID, Azure subscription ID)"`
	RoleID         string `json:"role_id" mapstructure:"role_id" validate:"required" flag:"role-id" desc:"Comma-separated role IDs to elevate with (max 5)"`
	OrganizationID string `json:"organization_id" mapstructure:"organization_id" flag:"organization-id" desc:"The ID of the organization/tenant. Required for Azure and AWS org accounts."`
}
