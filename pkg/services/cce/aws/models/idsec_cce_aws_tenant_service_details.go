package models

// TfIdsecCCEAWSGetTenantServiceDetails is the input for getting tenant service details.
// OPENAPI-CORRELATION: Input for GET /api/aws/tenant/service-details
type TfIdsecCCEAWSGetTenantServiceDetails struct {
	// No input parameters required for this endpoint
}

// TfIdsecCCEAWSTenantServiceDetails represents the tenant service details output.
// OPENAPI-CORRELATION: GetTenantServiceDetailsOutput
type TfIdsecCCEAWSTenantServiceDetails struct {
	// TenantID is the CyberArk tenant ID (UUID format).
	TenantID string `json:"tenantId" mapstructure:"tenant_id" desc:"CyberArk tenant ID (UUID format)"`
	// ServicesDetails contains service-specific details keyed by service name.
	ServicesDetails map[string]map[string]interface{} `json:"servicesDetails" mapstructure:"services_details" desc:"Service-specific details keyed by service name"`
}
