// Package models provides data structures for SCA group operations (Entra ID and Google Cloud groups).
package models

import scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"

// IdsecSCAGroupsEligibleTarget represents a single eligible group. Azure rows carry
// DirectoryID; GCP rows carry OrganizationID.
type IdsecSCAGroupsEligibleTarget struct {
	DirectoryID    string `json:"directoryId,omitempty" mapstructure:"directoryId" flag:"directory-id" desc:"The ID of the Entra directory that contains the group (AZURE)"`
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"organizationId" flag:"organization-id" desc:"The ID of the Google Cloud organization that contains the group (GCP)"`
	GroupID        string `json:"groupId" mapstructure:"groupId" flag:"group-id" desc:"The ID of the group (GCP: groups/{id})"`
	GroupName      string `json:"groupName" mapstructure:"groupName" flag:"group-name" desc:"The name of the group"`
}

// IdsecSCAGroupAccessElevateTarget is a single group target in an elevate request.
type IdsecSCAGroupAccessElevateTarget struct {
	GroupID string `json:"groupId" mapstructure:"group_id" desc:"The object ID of the Entra group to elevate into"`
}

// IdsecSCAGroupAccessElevateRequest is the API request body for POST /api/access/elevate/groups.
type IdsecSCAGroupAccessElevateRequest struct {
	CSP         string                             `json:"csp" mapstructure:"csp" desc:"The cloud provider (AZURE or GCP)"`
	DirectoryID string                             `json:"directoryId" mapstructure:"directory_id" desc:"The Entra directory (tenant) ID that contains the groups"`
	Targets     []IdsecSCAGroupAccessElevateTarget `json:"targets" mapstructure:"targets" desc:"One or more group targets to elevate into"`
}

// IdsecSCAGroupAccessElevateResult is a single result from an elevate request.
type IdsecSCAGroupAccessElevateResult struct {
	SessionID string                              `json:"sessionId,omitempty" mapstructure:"sessionId" desc:"The session ID of the elevate request"`
	GroupID   string                              `json:"groupId" mapstructure:"groupId" desc:"The group ID that was elevated"`
	GroupName string                              `json:"groupName,omitempty" mapstructure:"groupName" desc:"The name of the group that was elevated"`
	ErrorInfo *scamodels.IdsecSCAElevateErrorInfo `json:"errorInfo,omitempty" mapstructure:"errorInfo" desc:"Per-target error details when a requested group cannot be elevated"`
}

// IdsecSCAGroupAccessElevateResponseData is the inner response payload.
type IdsecSCAGroupAccessElevateResponseData struct {
	DirectoryID    string                             `json:"directoryId,omitempty" mapstructure:"directoryId" desc:"The directory (tenant) ID (AZURE)"`
	OrganizationID string                             `json:"organizationId,omitempty" mapstructure:"organizationId" desc:"The Google Cloud organization ID (GCP)"`
	CSP            string                             `json:"csp" mapstructure:"csp" desc:"The cloud provider"`
	Results        []IdsecSCAGroupAccessElevateResult `json:"results" mapstructure:"results" desc:"The list of elevate results"`
}

// IdsecSCAGroupAccessElevateResponse is the top-level elevate response.
type IdsecSCAGroupAccessElevateResponse struct {
	Response IdsecSCAGroupAccessElevateResponseData `json:"response" mapstructure:"response" desc:"The elevate response data"`
}

// IdsecSCAGroupAccessElevateActionRequest is the flat CLI schema for
// `idsec exec sca groupaccess elevate`.
type IdsecSCAGroupAccessElevateActionRequest struct {
	CSP            string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (AZURE or GCP)"`
	DirectoryID    string `json:"directory_id,omitempty" mapstructure:"directory_id" flag:"directory-id" desc:"The Entra directory (tenant) ID (required for AZURE)"`
	OrganizationID string `json:"organization_id,omitempty" mapstructure:"organization_id" flag:"organization-id" desc:"The Google Cloud organization ID (required for GCP)"`
	Groups         string `json:"groups" mapstructure:"groups" validate:"required" flag:"groups" desc:"Comma-separated group IDs to elevate access to (max 5; Google group IDs use the groups/{id} format)"`
}

// IdsecSCAListGroupTargetsResponse is the response from GET /access/{csp}/eligibility/groups.
type IdsecSCAListGroupTargetsResponse struct {
	Response  []IdsecSCAGroupsEligibleTarget `json:"response" mapstructure:"response" flag:"response" desc:"The list of groups for which you are eligible to request just-in-time membership"`
	Total     int                            `json:"total" mapstructure:"total" flag:"total" desc:"The total number of eligible groups"`
	NextToken string                         `json:"nextToken,omitempty" mapstructure:"nextToken" flag:"next-token" desc:"The token for retrieving the next page of results"`
}
