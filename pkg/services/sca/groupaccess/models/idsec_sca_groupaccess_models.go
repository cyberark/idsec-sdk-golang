// Package models provides data structures for SCA Entra ID group operations.
package models

import scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"

// IdsecSCAGroupsEligibleTarget represents a single eligible Entra ID group.
type IdsecSCAGroupsEligibleTarget struct {
	DirectoryID string `json:"directoryId" mapstructure:"directoryId" flag:"directory-id" desc:"The ID of the directory that contains the group"`
	GroupID     string `json:"groupId" mapstructure:"groupId" flag:"group-id" desc:"The ID of the group"`
	GroupName   string `json:"groupName" mapstructure:"groupName" flag:"group-name" desc:"The name of the group"`
}

// IdsecSCAGroupAccessElevateTarget is a single group target in an elevate request.
type IdsecSCAGroupAccessElevateTarget struct {
	GroupID string `json:"groupId" mapstructure:"group_id" desc:"The object ID of the Entra group to elevate into"`
}

// IdsecSCAGroupAccessElevateRequest is the API request body for POST /api/access/elevate/groups.
type IdsecSCAGroupAccessElevateRequest struct {
	CSP         string                             `json:"csp" mapstructure:"csp" desc:"The cloud provider (must be AZURE)"`
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
	DirectoryID string                             `json:"directoryId" mapstructure:"directoryId" desc:"The directory (tenant) ID"`
	CSP         string                             `json:"csp" mapstructure:"csp" desc:"The cloud provider"`
	Results     []IdsecSCAGroupAccessElevateResult `json:"results" mapstructure:"results" desc:"The list of elevate results"`
}

// IdsecSCAGroupAccessElevateResponse is the top-level elevate response.
type IdsecSCAGroupAccessElevateResponse struct {
	Response IdsecSCAGroupAccessElevateResponseData `json:"response" mapstructure:"response" desc:"The elevate response data"`
}

// IdsecSCAGroupAccessElevateActionRequest is the flat CLI schema for
// `idsec exec sca groupaccess elevate`.
type IdsecSCAGroupAccessElevateActionRequest struct {
	CSP         string `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"Cloud provider (must be AZURE)"`
	DirectoryID string `json:"directory_id" mapstructure:"directory_id" validate:"required" flag:"directory-id" desc:"The Entra directory (tenant) ID"`
	Groups      string `json:"groups" mapstructure:"groups" validate:"required" flag:"groups" desc:"Comma-separated group IDs to elevate into (max 50)"`
}

// IdsecSCAListGroupTargetsResponse is the response from GET /access/{csp}/eligibility/groups.
type IdsecSCAListGroupTargetsResponse struct {
	Response  []IdsecSCAGroupsEligibleTarget `json:"response" mapstructure:"response" flag:"response" desc:"The list of groups for which you are eligible to request just-in-time membership"`
	Total     int                            `json:"total" mapstructure:"total" flag:"total" desc:"The total number of eligible groups"`
	NextToken string                         `json:"nextToken,omitempty" mapstructure:"nextToken" flag:"next-token" desc:"The token for retrieving the next page of results"`
}
