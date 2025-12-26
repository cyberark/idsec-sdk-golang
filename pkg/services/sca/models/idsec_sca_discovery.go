// Package models provides data structures for SCA discovery operations including
// request, response and account info types relocated from the Cloud Access Policy module.
package models

// IdsecSCADiscoveryResponse represents the initial response returned after starting an SCA discovery job.
//
// Fields:
//   - Status: HTTP-like status code returned in the body.
//   - JobID: Unique identifier of the asynchronous discovery job.
//   - AlreadyRunning: Indicates a discovery job for the same scope was already in progress.
type IdsecSCADiscoveryResponse struct {
	Status         int    `json:"status" mapstructure:"status" flag:"status" desc:"HTTP-like status code returned in the body"`
	JobID          string `json:"job_id" mapstructure:"job_id" flag:"job-id" desc:"The ID of the job associated with the discovery process"`
	AlreadyRunning bool   `json:"already_running" mapstructure:"already_running" flag:"already-running" desc:"Indicates that a discovery job for the same scope was already in progress"`
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
	NewAccount bool   `json:"new_account" mapstructure:"new_account" validate:"required" flag:"new-account" desc:"Indicates whether the account is new to an already onboarded organization and needs to be discovered (e.g., a new AWS account in an already onboarded AWS organization; a new GCP project in an already onboarded Google Cloud organization; a new management group/subscription in an already onboarded Microsoft Entra ID tenant)"`
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
	CSP            string                       `json:"csp" mapstructure:"csp" validate:"required" flag:"csp" desc:"The cloud provider that hosts the workspace to discover (AWS | AZURE | GCP)"`
	OrganizationID string                       `json:"organization_id" mapstructure:"organization_id" validate:"required" flag:"organization-id" desc:"The ID of the organization to discover (AWS - The AWS organization ID | AZURE: Microsoft Entra ID Directory (Tenant) ID | GCP: Google Cloud organization ID)"`
	AccountInfo    IdsecSCADiscoveryAccountInfo `json:"account_info" mapstructure:"account_info" validate:"required,dive" flag:"account-info" desc:"A map of key-value pairs containing the account information of the workspace to discover"`
}
