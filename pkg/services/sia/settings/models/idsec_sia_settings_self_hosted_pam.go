package models

// IdsecSIASettingsSelfHostedPam represents the self-hosted PAM configuration for SIA settings.
//
// This model contains configuration options for integrating self-hosted Privileged Access Management (PAM)
// solutions within the Idsec SIA service. It includes settings for connector pool identification,
// load balancing options, PVWA base URL, service user credentials, and tenant type to facilitate
// secure and efficient management of privileged access through self-hosted PAM systems.
type IdsecSIASettingsSelfHostedPam struct {
	ConnectorPoolID     *string `json:"connector_pool_id,omitempty" mapstructure:"connector_pool_id,omitempty" flag:"connector-pool-id" desc:"The ID of the connector pool to use for PAM Self-Hosted."`
	IsIPBasedLBEnabled  *bool   `json:"is_ip_based_lb_enabled,omitempty" mapstructure:"is_ip_based_lb_enabled,omitempty" flag:"is-ip-based-lb-enabled" desc:"Indicates whether IP-based load balancing is enabled for PAM Self-Hosted."`
	PVWABaseURL         *string `json:"pvwa_base_url,omitempty" mapstructure:"pvwa_base_url,omitempty" flag:"pvwa-base-url" desc:"The base URL of the PVWA for PAM Self-Hosted."`
	ServiceUserSecretID *string `json:"service_user_secret_id,omitempty" mapstructure:"service_user_secret_id,omitempty" flag:"service-user-secret-id" desc:"The secret ID of the service user for PAM Self-Hosted."`
	TenantType          *string `json:"tenant_type,omitempty" mapstructure:"tenant_type,omitempty" flag:"tenant-type" choices:"PCLOUD,SELF_HOSTED" desc:"The type of tenant for PAM Self-Hosted (PCLOUD,SELF_HOSTED)."`
}
