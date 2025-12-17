package models

import (
	"time"

	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// Default scan probe configuration constants for organization account operations
const (
	// defaultScanProbeMaxRetries is the default maximum number of scan probe attempts when account is not discovered
	defaultScanProbeMaxRetries = 20
	// defaultScanProbeInterval is the default wait time between scan probes
	defaultScanProbeInterval = 3 * time.Second
)

// IdsecCCEAWSAddOrganizationAccount is the input for adding an AWS account to an organization.
// OPENAPI-CORRELATION: AwsProgrammaticAddAccountBodyInput + path parameter
type IdsecCCEAWSAddOrganizationAccount struct {
	// OrganizationID is the CCE onboarding ID of the parent organization.
	OrganizationID string `json:"organizationId" mapstructure:"parent_organization_id" validate:"required" desc:"CCE onboarding ID of the parent organization"`
	// AccountID is the AWS account ID (12 digits) to add to the organization.
	AccountID string `json:"accountId" mapstructure:"account_id" validate:"required,len=12,numeric" desc:"AWS account ID (12 digits) to add to the organization"`
	// Services is the list of services to onboard with their resource configurations.
	Services []ccemodels.IdsecCCEServiceInput `json:"services" mapstructure:"services" validate:"required,min=1,dive" desc:"List of services to onboard with their resource configurations"`
}

// IdsecCCEAWSAddedOrganizationAccount is the output returned after adding an account to an organization.
// OPENAPI-CORRELATION: AwsProgrammaticAddAccountOrganizationOutput
type IdsecCCEAWSAddedOrganizationAccount struct {
	// ID is the CCE onboarding ID for the added account.
	ID string `json:"id" mapstructure:"id" desc:"CCE onboarding ID for the added account"`
}

// IdsecCCEAWSScanOrganization is the input for triggering an AWS organization scan.
// OPENAPI-CORRELATION: Input for POST /api/aws/organizations/scan
type IdsecCCEAWSScanOrganization struct {
	// OrganizationID is the optional AWS organization ID to scan a specific organization.
	OrganizationID string `json:"organizationId,omitempty" mapstructure:"organization_id,omitempty" desc:"Optional CCE AWS organization ID to scan a specific organization"`
}

// IdsecCCEAWSScanResult is the output returned after triggering an AWS organization scan.
// OPENAPI-CORRELATION: AwsScanOnDemandOutput
type IdsecCCEAWSScanResult struct {
	// Empty response from scan operation
}

// IdsecCCEAWSAddOrganizationAccountSync is the input for adding an AWS account to an organization with sync/retry logic.
// This struct embeds IdsecCCEAWSAddOrganizationAccount and adds optional scan probe retry configuration.
type IdsecCCEAWSAddOrganizationAccountSync struct {
	IdsecCCEAWSAddOrganizationAccount `mapstructure:",squash"`
	// ScanProbeMaxRetries is the maximum number of scan probe attempts when account is not discovered (default: 20)
	ScanProbeMaxRetries *int `json:"scanProbeMaxRetries,omitempty" mapstructure:"scan_probe_max_retries" desc:"Maximum scan probe attempts when account not discovered (default: 20)"`
	// ScanProbeIntervalSeconds is the wait time between scan probes in seconds (default: 3)
	ScanProbeIntervalSeconds *int `json:"scanProbeIntervalSeconds,omitempty" mapstructure:"scan_probe_interval_seconds" desc:"Wait time between scan probes in seconds (default: 3)"`
}

// GetScanProbeMaxRetries returns the ScanProbeMaxRetries value or default of defaultScanProbeMaxRetries
func (s *IdsecCCEAWSAddOrganizationAccountSync) GetScanProbeMaxRetries() int {
	if s.ScanProbeMaxRetries != nil {
		return *s.ScanProbeMaxRetries
	}
	return defaultScanProbeMaxRetries
}

// GetScanProbeInterval returns the scan probe interval or default of defaultScanProbeInterval
func (s *IdsecCCEAWSAddOrganizationAccountSync) GetScanProbeInterval() time.Duration {
	if s.ScanProbeIntervalSeconds != nil {
		return time.Duration(*s.ScanProbeIntervalSeconds) * time.Second
	}
	return defaultScanProbeInterval
}

// ToAddOrganizationAccount converts to the simple input struct (without retry options)
func (s *IdsecCCEAWSAddOrganizationAccountSync) ToAddOrganizationAccount() *IdsecCCEAWSAddOrganizationAccount {
	return &IdsecCCEAWSAddOrganizationAccount{
		OrganizationID: s.OrganizationID,
		AccountID:      s.AccountID,
		Services:       s.Services,
	}
}
