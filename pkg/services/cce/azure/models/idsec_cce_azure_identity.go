package models

// IdsecCCEWorkloadFederation represents workload federation identity details for Azure services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: WorkloadFederation
type IdsecCCEWorkloadFederation struct {
	// IdentityUserID is the identity user identifier.
	IdentityUserID string `json:"identity_user_id,omitempty" mapstructure:"identity_user_id,omitempty" validate:"required" desc:"Identity user identifier"`
	// IdentityAppID is the identity application identifier.
	IdentityAppID string `json:"identity_app_id,omitempty" mapstructure:"identity_app_id,omitempty" validate:"required" desc:"Identity application identifier"`
	// IdentityAppIssuer is the identity application issuer.
	IdentityAppIssuer string `json:"identity_app_issuer,omitempty" mapstructure:"identity_app_issuer,omitempty" validate:"required" desc:"Identity application issuer"`
	// IdentityAppAudience is the identity application audience.
	IdentityAppAudience string `json:"identity_app_audience,omitempty" mapstructure:"identity_app_audience,omitempty" validate:"required" desc:"Identity application audience"`
}

// TfIdsecCCEAzureGetIdentityParams is the input for retrieving Azure identity federation parameters for active services.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: Input for GET /api/azure/identity_params
type TfIdsecCCEAzureGetIdentityParams struct {
}

// TfIdsecCCEAzureIdentityParams represents the output of retrieving Azure identity parameters.
// ⚠️  DEPRECATED: This struct is deprecated and should not be used.
// ⚠️  It exists only for compatibility with Terraform provider.
// OPENAPI-CORRELATION: GetIdentityParamsOutput
type TfIdsecCCEAzureIdentityParams struct {
	// IdentityParams contains a map of service names to their workload federation identity details.
	// Keys are service names (e.g., "cds", "dpa", "cloud_onboarding") and values are identity objects.
	IdentityParams map[string]IdsecCCEWorkloadFederation `json:"identity_params" mapstructure:"identity_params" desc:"Map of service names to identity parameters"`
}
