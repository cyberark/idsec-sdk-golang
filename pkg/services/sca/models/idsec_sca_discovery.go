// Package models provides data structures for SCA discovery operations including
// request, response and account info types relocated from the UAP SCA module.
package models

// IdsecSCADiscoveryResponse represents the initial response returned after starting an SCA discovery job.
//
// Fields:
//   - Status: HTTP-like status code returned in the body.
//   - JobID: Unique identifier of the asynchronous discovery job.
//   - AlreadyRunning: Indicates a discovery job for the same scope was already in progress.
//
// NOTE: Relocated from pkg/services/uap/sca/models/idsec_sca_discovery.go.
type IdsecSCADiscoveryResponse struct {
	Status         int    `json:"status" mapstructure:"status" flag:"status" desc:"HTTP-like status code returned in the body."`
	JobID          string `json:"job_id" mapstructure:"job_id" flag:"job-id" desc:"The unique identifier of the job associated with the discovery process."`
	AlreadyRunning bool   `json:"already_running" mapstructure:"already_running" flag:"already-running" desc:"Indicates a discovery job for the same scope was already in progress."`
}

// IdsecSCADiscoveryAccountInfo holds account related discovery parameters.
//
// Fields:
//   - ID: Workspace / Account identifier (required).
//   - NewAccount: Flag indicating new account onboarding.
//
// NOTE: Relocated.
type IdsecSCADiscoveryAccountInfo struct {
	ID         string `json:"id" mapstructure:"id" validate:"required" flag:"id" desc:"The ID of the workspace to discover (AWS - AWS account ID | Azure - Management group, subscription, or resource group ID | GCP - Google Cloud project ID )"`
	NewAccount bool   `json:"new_account" mapstructure:"new_account" validate:"required" flag:"new-account" desc:"Indicates whether the account is new to an organization, and has not yet been onboarded."`
}

// IdsecSCADiscoveryRequest represents a discovery operation input for SCA policies.
//
// Fields:
//   - CSP: Cloud service provider identifier (aws|azure|gcp).
//   - OrganizationID: Root organization / subscription / folder id.
//   - AccountInfo: Nested account/workspace info payload.
//
// NOTE: Relocated.
type IdsecSCADiscoveryRequest struct {
	CSP            string                       `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"The cloud provider associated with the workspace to discover (AWS | AZURE | GCP)"`
	OrganizationID string                       `json:"organization_id" mapstructure:"organization_id" validate:"required" flag:"organization-id" desc:"The ID of the organization to discover (AWS - The AWS organization ID | AZURE: Azure tenant ID GCP: Google Cloud organization ID)"`
	AccountInfo    IdsecSCADiscoveryAccountInfo `json:"account_info" mapstructure:"account_info" validate:"required,dive" flag:"account-info" desc:"A map of key-value pairs with the account info"`
}
