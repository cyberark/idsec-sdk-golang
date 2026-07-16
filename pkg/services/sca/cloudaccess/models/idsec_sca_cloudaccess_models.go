// Package models provides data structures for SCA cloudaccess operations.
package models

import (
	"encoding/json"

	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

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

// IdsecSCAEligibleTarget represents a single eligible cloudaccess target returned by
// the SCA eligibility API (GET /access/{csp}/eligibility).
//
// Corresponds to the CommonEligibleTarget + CSP-specific allOf schemas in the API spec:
//   - AWSAccountEligibleTarget    (workspaceType: ACCOUNT)
//   - AWSOrgAccountEligibleTarget (workspaceType: ACCOUNT, organizationId present)
//   - AzureEligibleTarget         (workspaceType: RESOURCE | RESOURCE_GROUP | SUBSCRIPTION | MANAGEMENT_GROUP | DIRECTORY)
//
// Fields:
//   - WorkspaceID:     The ID of the workspace (required by API).
//   - WorkspaceName:   The display name of the workspace (max 255 chars).
//   - RoleInfo:        The role with which the user is eligible to access the workspace.
//   - OrganizationID:  The ID of the containing organization/tenant (AWS org or Azure tenant).
//   - WorkspaceType:   The type of the workspace (enum varies per CSP).
type IdsecSCAEligibleTarget struct {
	WorkspaceID    string           `json:"workspaceId" mapstructure:"workspaceId" flag:"workspace-id" desc:"The ID of the workspace"`
	WorkspaceName  string           `json:"workspaceName,omitempty" mapstructure:"workspaceName" flag:"workspace-name" desc:"The display name of the workspace"`
	RoleInfo       IdsecSCARoleInfo `json:"role" mapstructure:"roleInfo" flag:"role-info" desc:"The role with which you are eligible to access the workspace"`
	OrganizationID string           `json:"organizationId,omitempty" mapstructure:"organizationId" flag:"organization-id" desc:"The ID of the organization or tenant that contains the workspace (AWS org ID | Azure Entra tenant ID)"`
	WorkspaceType  string           `json:"workspaceType,omitempty" mapstructure:"workspaceType" flag:"workspace-type" desc:"The type of the workspace (AWS: ACCOUNT | AZURE: RESOURCE, RESOURCE_GROUP, SUBSCRIPTION, MANAGEMENT_GROUP, DIRECTORY)"`
}

// IdsecSCAListTargetsResponse is the response from GET /access/{csp}/eligibility.
//
// Fields:
//   - Response:  List of eligible cloudaccess targets.
//   - Total:     Total number of eligible targets across all pages.
//   - NextToken: Pagination token to retrieve the next page; empty when no more pages.
type IdsecSCAListTargetsResponse struct {
	Response  []IdsecSCAEligibleTarget               `json:"response" mapstructure:"response" flag:"response" desc:"The list of targets you are eligible to access"`
	Responses map[string]IdsecSCAListTargetsResponse `json:"-" mapstructure:"responses" flag:"responses" desc:"Targets grouped by CSP when listing all cloud providers"`
	Total     int                                    `json:"total" mapstructure:"total" flag:"total" desc:"The total number of targets you are eligible to access"`
	NextToken string                                 `json:"nextToken,omitempty" mapstructure:"nextToken" flag:"next-token" desc:"The token for retrieving the next page of results"`
	Errors    scamodels.IdsecSCAListTargetsErrors    `json:"-" mapstructure:"errors" flag:"errors" desc:"Per-CSP errors returned when listing all cloud providers"`
}

func (r IdsecSCAListTargetsResponse) MarshalJSON() ([]byte, error) {
	if len(r.Responses) == 0 && len(r.Errors) == 0 {
		type alias IdsecSCAListTargetsResponse
		return json.Marshal(alias(r))
	}

	return scamodels.MarshalListTargetsAllCSPsJSON(r.Responses, r.Errors)
}

// IdsecSCACloudAccessElevateTarget describes a single workspace-role target for elevation.
//
// WorkspaceID is required. Exactly one of RoleID or RoleName must be provided — not both.
//
// Notes:
//   - The workspace ID for all Azure targets must be the same.
type IdsecSCACloudAccessElevateTarget struct {
	WorkspaceID string `json:"workspaceId" mapstructure:"workspaceId" flag:"workspace-id" desc:"The ID of the workspace to which access is being requested. For Azure, the workspace ID for all targets must be the same."`
	RoleID      string `json:"roleId,omitempty" mapstructure:"roleId,omitempty" flag:"role-id" desc:"The ID of the role with which you're eligible to access the target. Provide either role-id or role-name, but not both."`
	RoleName    string `json:"roleName,omitempty" mapstructure:"roleName,omitempty" flag:"role-name" desc:"The name of the role with which you're eligible to access the target. Provide either role-name or role-id, but not both."`
}

// IdsecSCACloudAccessElevateRequest is the POST body for POST /access/elevate.
//
// Targets constraints (minItems: 1, maxItems: 5):
//   - Standalone AWS account: max 1 target.
//   - AWS account in an org: max 1 target.
//   - Azure subscriptions/resource groups/resources: max 5.
//
// OrganizationID is not relevant for standalone AWS accounts.
type IdsecSCACloudAccessElevateRequest struct {
	CSP            string                             `json:"csp" mapstructure:"csp" flag:"csp" desc:"The cloud provider that hosts the workspaces for which access is required. Enum: AWS | AZURE"`
	Targets        []IdsecSCACloudAccessElevateTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"The targets (workspace + role) for which access is being requested. Min: 1, Max: 5 (exact limit varies by CSP and configuration)"`
	OrganizationID string                             `json:"organizationId,omitempty" mapstructure:"organizationId,omitempty" flag:"organization-id" desc:"The ID of the organization that contains the workspaces. All specified workspaces and roles must be part of this organization. Not relevant for standalone AWS accounts."`
}

// IdsecSCACloudAccessElevateResult represents one result entry in the elevate response.
//
// On success, AccessCredentials contains a JSON-encoded string (double-encoded) with
// aws_access_key, aws_secret_access_key, and aws_session_token.
// On failure (e.g. user not eligible), ErrorInfo is populated and AccessCredentials is empty.
type IdsecSCACloudAccessElevateResult struct {
	WorkspaceID       string                              `json:"workspaceId" mapstructure:"workspaceId"`
	RoleID            string                              `json:"roleId" mapstructure:"roleId"`
	SessionID         string                              `json:"sessionId,omitempty" mapstructure:"sessionId,omitempty"`
	AccessCredentials string                              `json:"accessCredentials,omitempty" mapstructure:"accessCredentials,omitempty"`
	ErrorInfo         *scamodels.IdsecSCAElevateErrorInfo `json:"errorInfo,omitempty" mapstructure:"errorInfo,omitempty"`
}

// IdsecSCACloudAccessElevateResponseBody is the inner "response" object in the elevate API reply.
type IdsecSCACloudAccessElevateResponseBody struct {
	OrganizationID string                             `json:"organizationId" mapstructure:"organizationId"`
	CSP            string                             `json:"csp" mapstructure:"csp"`
	Results        []IdsecSCACloudAccessElevateResult `json:"results" mapstructure:"results"`
}

// IdsecSCACloudAccessElevateResponse is the top-level elevate API reply.
type IdsecSCACloudAccessElevateResponse struct {
	Response IdsecSCACloudAccessElevateResponseBody `json:"response" mapstructure:"response"`
}

// IdsecSCACloudAccessElevateActionRequest is the flat CLI schema for
// `idsec exec sca cloudaccess elevate`.
//
// Registered in ActionToSchemaMap so the framework generates cobra flags automatically.
// The framework maps "elevate" → Elevate() by naming convention (same as list-targets → ListTargets()).
type IdsecSCACloudAccessElevateActionRequest struct {
	CSP            string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AWS, AZURE)"`
	WorkspaceID    string `json:"workspace_id" mapstructure:"workspace_id" validate:"required" flag:"workspace-id" desc:"The ID of the workspace (e.g. AWS account ID, Azure subscription ID)"`
	RoleIDs        string `json:"roleIds" mapstructure:"roleIds" validate:"required" flag:"roleIds" desc:"Comma-separated role IDs to elevate with (max 5)"`
	OrganizationID string `json:"organization_id" mapstructure:"organization_id" flag:"organization-id" desc:"The ID of the organization/tenant. Required for Azure and AWS org accounts."`
}
